package com.company.incert.kms.adapter.in.seed;

import com.company.incert.kms.application.port.out.CertificateRepository;
import com.company.incert.kms.application.port.out.OutboxWriter;
import com.company.incert.kms.domain.Certificate;
import com.company.incert.kms.domain.CertificateStatus;
import com.company.incert.kms.domain.CertificateStatusChangedEvent;
import com.company.incert.kms.domain.RevocationReason;
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
    private final OutboxWriter outboxWriter;

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

        // 4. Build intermediate CA cert
        X500Name intName = new X500Name("CN=Incert Test CA,O=Incert,C=CH");
        BigInteger intSerial   = BigInteger.probablePrime(128, new Random());
        Date intNotBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date intNotAfter  = Date.from(Instant.now().plus(1825, ChronoUnit.DAYS));

        X509v3CertificateBuilder intBuilder = new X509v3CertificateBuilder(
                rootName, intSerial, intNotBefore, intNotAfter, intName,
                SubjectPublicKeyInfo.getInstance(intKp.getPublic().getEncoded())
        );
        intBuilder.addExtension(Extension.subjectKeyIdentifier,  false, extUtils.createSubjectKeyIdentifier(intKp.getPublic()));
        intBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(rootCertHolder));
        intBuilder.addExtension(Extension.basicConstraints, true,  new BasicConstraints(1));
        intBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        X509CertificateHolder intCertHolder = intBuilder.build(rootSigner);
        X509Certificate intCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(intCertHolder);

        // 5. Compute issuer hashes for intermediate CA
        //    issuerKeyHash:  SHA-1 of the BIT STRING value of the SubjectPublicKeyInfo
        //    issuerNameHash: SHA-1 of the DER-encoded issuer DN (= root CA's subject DN)
        //    For end-entity certs the CertID issuer is the *intermediate* CA, so both hashes
        //    are computed over the intermediate's subject DN and public key (RFC 6960 §4.1.1).
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] intKeyHashBytes  = sha1.digest(intCertHolder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
        sha1.reset();
        byte[] intNameHashBytes = sha1.digest(intCertHolder.getSubject().getEncoded());
        String intKeyHashHex  = HexFormat.of().formatHex(intKeyHashBytes);
        String intNameHashHex = HexFormat.of().formatHex(intNameHashBytes);

        // 6. Generate 50 end-entity certificates
        List<Certificate> certs = new ArrayList<>();
        Random rng = new Random(42); // deterministic seed for reproducibility
        // End-entity keys use RSA 2048 to keep seeding fast; CAs use RSA 3072.
        KeyPairGenerator eeKpg = KeyPairGenerator.getInstance("RSA", "BC");
        eeKpg.initialize(2048);

        for (int i = 0; i < 50; i++) {
            KeyPair eeKp = eeKpg.generateKeyPair();
            String cn    = "test-ee-" + String.format("%03d", i + 1) + ".incert.ch";
            X500Name eeName   = new X500Name("CN=" + cn + ",O=Incert,C=CH");
            BigInteger eeSerial = BigInteger.probablePrime(128, rng);

            // Mix: 40 valid, 5 near-expiry, 5 expired
            Instant eeNotBefore, eeNotAfter;
            if (i < 40) {
                eeNotBefore = Instant.now().minus(30, ChronoUnit.DAYS);
                eeNotAfter  = Instant.now().plus(730, ChronoUnit.DAYS);
            } else if (i < 45) {
                eeNotBefore = Instant.now().minus(360, ChronoUnit.DAYS);
                eeNotAfter  = Instant.now().plus(7, ChronoUnit.DAYS);
            } else {
                eeNotBefore = Instant.now().minus(400, ChronoUnit.DAYS);
                eeNotAfter  = Instant.now().minus(35, ChronoUnit.DAYS);
            }

            ContentSigner intSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC").build(intKp.getPrivate());
            X509v3CertificateBuilder eeBuilder = new X509v3CertificateBuilder(
                    intName, eeSerial,
                    Date.from(eeNotBefore), Date.from(eeNotAfter),
                    eeName,
                    SubjectPublicKeyInfo.getInstance(eeKp.getPublic().getEncoded())
            );
            eeBuilder.addExtension(Extension.subjectKeyIdentifier,  false, extUtils.createSubjectKeyIdentifier(eeKp.getPublic()));
            eeBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(intCertHolder));
            eeBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

            X509CertificateHolder eeCertHolder = eeBuilder.build(intSigner);
            X509Certificate eeCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(eeCertHolder);

            String pem      = toPem(eeCert);
            // Canonical serial encoding shared with ocsp-app: hex of the DER INTEGER content bytes
            String serialHex = HexFormat.of().formatHex(eeSerial.toByteArray());

            Certificate domainCert = new Certificate(
                    serialHex, intName.toString(), intKeyHashHex, intNameHashHex,
                    eeName.toString(), eeNotBefore, eeNotAfter,
                    CertificateStatus.GOOD, null, null, pem, 0
            );
            certs.add(domainCert);
        }

        // 7. Save all certs and write initial snapshot events to outbox
        for (Certificate cert : certs) {
            Certificate saved = certRepository.save(cert);
            outboxWriter.write(CertificateStatusChangedEvent.from(saved));
        }

        // 8. Export PKI artifacts to ./data/pki/ and /data/pki/
        for (String dirStr : List.of("data/pki", "/data/pki")) {
            try {
                Path pkiDir = Path.of(dirStr);
                Files.createDirectories(pkiDir);
                writePem(pkiDir.resolve("root-ca.pem"), rootCert);
                writePem(pkiDir.resolve("intermediate-ca.pem"), intCert);
                // Write CA chain (intermediate first, then root)
                try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(pkiDir.resolve("ca-chain.pem")))) {
                    pw.print(toPem(intCert));
                    pw.print(toPem(rootCert));
                }
                // Export 5 sample EE PEMs for openssl testing
                for (int i = 0; i < Math.min(5, certs.size()); i++) {
                    Path eeFile = pkiDir.resolve("ee-" + String.format("%02d", i + 1) + ".pem");
                    Files.writeString(eeFile, certs.get(i).pemEncoded());
                }
                // Write intermediate CA private key (TEST ONLY — for SoftHSM init)
                try (JcaPEMWriter pw = new JcaPEMWriter(
                        Files.newBufferedWriter(pkiDir.resolve("intermediate-ca-key.pem.TESTONLY")))) {
                    pw.writeObject(intKp.getPrivate());
                }
                writePem(pkiDir.resolve("intermediate-ca-cert.pem"), intCert);

                // Store issuer hashes and serials for reference / e2e tests
                Files.writeString(pkiDir.resolve("issuer-key-hash.txt"), intKeyHashHex + "\n");
                Files.writeString(pkiDir.resolve("issuer-name-hash.txt"), intNameHashHex + "\n");
                StringBuilder serials = new StringBuilder();
                for (Certificate c : certs) serials.append(c.serialNumberHex()).append("\n");
                Files.writeString(pkiDir.resolve("serials.txt"), serials.toString());

                log.info("PKI artifacts exported to {}", pkiDir.toAbsolutePath());
            } catch (Exception e) {
                log.warn("Could not export PKI to {}: {}", dirStr, e.getMessage());
            }
        }
    }

    private static String toPem(X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(cert);
        }
        return sw.toString();
    }

    private static void writePem(Path file, X509Certificate cert) throws Exception {
        Files.writeString(file, toPem(cert));
    }
}
