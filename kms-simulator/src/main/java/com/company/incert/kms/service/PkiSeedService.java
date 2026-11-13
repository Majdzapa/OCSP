package com.company.incert.kms.service;

import com.company.incert.kms.entity.Certificate;
import com.company.incert.kms.entity.CertificateStatus;
import com.company.incert.kms.entity.CertificateStatusEvent;
import com.company.incert.kms.entity.OutboxEvent;
import com.company.incert.kms.entity.RevocationReason;
import com.company.incert.kms.repository.CertificateRepository;
import com.company.incert.kms.repository.OutboxEventRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.transaction.annotation.Transactional;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Generates a fake test PKI on startup (dev + test profiles only).
 * Creates: root CA → intermediate "Incert Test CA" → 50 end-entity certs.
 * Exports CA cert and sample EE PEMs to ./data/pki/ for openssl testing.
 */
@Slf4j
@Configuration
@Profile({"dev", "test"})
@RequiredArgsConstructor
public class PkiSeedService {

    private final CertificateRepository certRepository;
    private final OutboxEventRepository outboxRepo;
    private final ObjectMapper objectMapper;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Bean
    public ApplicationRunner pkiSeeder() {
        return args -> {
            if (certRepository.count() > 0) {
                log.info("PKI already seeded ({} certs), skipping", certRepository.count());
                return;
            }
            log.info("Seeding test PKI...");
            seedPki();
            log.info("PKI seeding complete: {} certificates", certRepository.count());
        };
    }

    @Transactional
    public void seedPki() throws Exception {
        // 1. Generate root CA key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(3072);
        KeyPair rootKp = kpg.generateKeyPair();

        // 2. Generate intermediate CA key pair
        KeyPair intKp = kpg.generateKeyPair();

        // 3. Build root CA cert (self-signed)
        X500Name rootName = new X500Name("CN=Incert Test Root CA,O=Incert,C=CH");
        Date rootNotBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date rootNotAfter  = Date.from(Instant.now().plus(3650, ChronoUnit.DAYS));
        BigInteger rootSerial = BigInteger.probablePrime(128, new Random());

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        ContentSigner rootSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(rootKp.getPrivate());

        X509v3CertificateBuilder rootBuilder = new X509v3CertificateBuilder(
                rootName, rootSerial, rootNotBefore, rootNotAfter, rootName,
                SubjectPublicKeyInfo.getInstance(rootKp.getPublic().getEncoded())
        );
        rootBuilder.addExtension(Extension.subjectKeyIdentifier,  false, extUtils.createSubjectKeyIdentifier(rootKp.getPublic()));
        rootBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(rootKp.getPublic()));
        rootBuilder.addExtension(Extension.basicConstraints, true,  new BasicConstraints(true));
        rootBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        X509CertificateHolder rootCertHolder = rootBuilder.build(rootSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(rootCertHolder);

        // 4. Build intermediate CA cert (signed by root CA)
        X500Name intName = new X500Name("CN=Incert Test CA,O=Incert,C=CH");
        Date intNotBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date intNotAfter  = Date.from(Instant.now().plus(1825, ChronoUnit.DAYS));
        BigInteger intSerial = BigInteger.probablePrime(128, new Random());

        X509v3CertificateBuilder intBuilder = new X509v3CertificateBuilder(
                rootName, intSerial, intNotBefore, intNotAfter, intName,
                SubjectPublicKeyInfo.getInstance(intKp.getPublic().getEncoded())
        );
        intBuilder.addExtension(Extension.subjectKeyIdentifier,   false, extUtils.createSubjectKeyIdentifier(intKp.getPublic()));
        intBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(rootKp.getPublic()));
        intBuilder.addExtension(Extension.basicConstraints, true,  new BasicConstraints(0)); // pathLen=0
        intBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        X509CertificateHolder intCertHolder = intBuilder.build(rootSigner);
        X509Certificate intCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(intCertHolder);

        // Compute issuer hashes for intermediate CA
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        String issuerKeyHashHex  = HexFormat.of().formatHex(sha1.digest(intKp.getPublic().getEncoded()));
        String issuerNameHashHex = HexFormat.of().formatHex(sha1.digest(intCertHolder.getSubject().getEncoded()));

        log.info("Intermediate CA: subject='{}' keyHash={} nameHash={}",
                intName, issuerKeyHashHex, issuerNameHashHex);

        // 5. Generate 50 end-entity certs
        ContentSigner intSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(intKp.getPrivate());

        List<Certificate> certsToSave = new ArrayList<>();
        List<X509Certificate> sampleEeCerts = new ArrayList<>();

        for (int i = 1; i <= 50; i++) {
            KeyPair eeKp = kpg.generateKeyPair();
            BigInteger eeSerial = BigInteger.probablePrime(128, new Random());
            String serialHex = HexFormat.of().formatHex(eeSerial.toByteArray());

            X500Name eeSubject = new X500Name(String.format("CN=service-%03d.incert.internal,O=Incert,C=CH", i));
            Date eeNotBefore = Date.from(Instant.now().minus(30, ChronoUnit.DAYS));
            Date eeNotAfter  = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

            X509v3CertificateBuilder eeBuilder = new X509v3CertificateBuilder(
                    intName, eeSerial, eeNotBefore, eeNotAfter, eeSubject,
                    SubjectPublicKeyInfo.getInstance(eeKp.getPublic().getEncoded())
            );
            eeBuilder.addExtension(Extension.subjectKeyIdentifier,   false, extUtils.createSubjectKeyIdentifier(eeKp.getPublic()));
            eeBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(intKp.getPublic()));
            eeBuilder.addExtension(Extension.basicConstraints, true,  new BasicConstraints(false));
            eeBuilder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

            // AIA OCSP responder URL
            GeneralName ocspLocation = new GeneralName(GeneralName.uniformResourceIdentifier,
                    "http://localhost:8080/ocsp");
            AccessDescription aiaOcsp = new AccessDescription(AccessDescription.id_ad_ocsp, ocspLocation);
            AuthorityInformationAccess aia = new AuthorityInformationAccess(aiaOcsp);
            eeBuilder.addExtension(Extension.authorityInfoAccess, false, aia);

            X509CertificateHolder eeCertHolder = eeBuilder.build(intSigner);
            X509Certificate eeCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(eeCertHolder);

            // Initially: #1-#5 revoked, rest GOOD
            CertificateStatus status = (i <= 5) ? CertificateStatus.REVOKED : CertificateStatus.GOOD;
            Instant revTime = (status == CertificateStatus.REVOKED)
                    ? Instant.now().minus(i * 2L, ChronoUnit.DAYS) : null;
            RevocationReason reason = (status == CertificateStatus.REVOKED)
                    ? RevocationReason.KEY_COMPROMISE : null;

            Certificate entity = Certificate.builder()
                    .serialNumberHex(serialHex)
                    .issuerDn(intName.toString())
                    .issuerKeyHashHex(issuerKeyHashHex)
                    .issuerNameHashHex(issuerNameHashHex)
                    .subjectDn(eeSubject.toString())
                    .notBefore(eeNotBefore.toInstant())
                    .notAfter(eeNotAfter.toInstant())
                    .status(status)
                    .revocationTime(revTime)
                    .revocationReason(reason)
                    .pemEncoded(toPem(eeCert))
                    .sequence(0L)
                    .build();

            certsToSave.add(entity);
            if (i <= 3) sampleEeCerts.add(eeCert);
        }

        // Persist all certs and write initial outbox events
        for (Certificate cert : certsToSave) {
            Certificate saved = certRepository.save(cert);
            writeOutbox(CertificateStatusEvent.from(saved));
        }

        // 6. Export CA chain and sample certs to ./data/pki/ for openssl testing
        exportPkiArtifacts(rootCert, intCert, sampleEeCerts);
    }

    private void writeOutbox(CertificateStatusEvent event) {
        try {
            String payload = objectMapper.writeValueAsString(event);
            String eventKey = event.issuerKeyHashHex() + ":" + event.serialNumberHex();
            OutboxEvent outbox = OutboxEvent.builder()
                    .eventId(event.eventId())
                    .topic("incert.certificate.status.v1")
                    .eventKey(eventKey)
                    .payload(payload)
                    .createdAt(Instant.now())
                    .sent(false)
                    .build();
            outboxRepo.save(outbox);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize outbox event during seeding", e);
        }
    }

    private void exportPkiArtifacts(X509Certificate root, X509Certificate intermediate,
                                    List<X509Certificate> sampleEe) {
        try {
            Path pkiDir = Paths.get("./data/pki");
            Files.createDirectories(pkiDir);

            writeFile(pkiDir.resolve("root-ca.pem"), toPem(root));
            writeFile(pkiDir.resolve("ca.pem"), toPem(intermediate));
            writeFile(pkiDir.resolve("ca-chain.pem"), toPem(intermediate) + toPem(root));

            for (int i = 0; i < sampleEe.size(); i++) {
                writeFile(pkiDir.resolve(String.format("ee-%03d.pem", i + 1)), toPem(sampleEe.get(i)));
            }

            // Write issuer hash info file for reference
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            String keyHash  = HexFormat.of().formatHex(sha1.digest(intermediate.getPublicKey().getEncoded()));
            String nameHash = HexFormat.of().formatHex(sha1.digest(intermediate.getSubjectX500Principal().getEncoded()));
            String meta = "ISSUER_KEY_HASH=" + keyHash + "\nISSUER_NAME_HASH=" + nameHash + "\n";
            writeFile(pkiDir.resolve("issuer-hashes.env"), meta);

            log.info("Exported test PKI artifacts to {}", pkiDir.toAbsolutePath());
        } catch (Exception e) {
            log.warn("Could not export PKI artifacts: {}", e.getMessage());
        }
    }

    private static String toPem(Object obj) throws IOException {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(obj);
        }
        return sw.toString();
    }

    private static void writeFile(Path path, String content) throws IOException {
        Files.writeString(path, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }
}

