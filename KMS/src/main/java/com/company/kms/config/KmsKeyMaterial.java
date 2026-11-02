package com.company.kms.config;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Generates and holds the in-memory KMS key material for the mock service.
 *
 * <p>On startup:
 * <ol>
 *   <li>Generates an RSA-2048 key pair.</li>
 *   <li>Issues a self-signed X.509 certificate with:
 *       <ul>
 *         <li>Extended Key Usage: {@code id-kp-OCSPSigning}</li>
 *         <li>OCSP No-Check extension (no CRL needed for the signer itself)</li>
 *         <li>90-day validity</li>
 *       </ul>
 *   </li>
 * </ol>
 *
 * <p>The private key is held in a Java {@link KeyPair} — no HSM in dev mode.
 * In production, the private key would never leave the HSM.
 */
@Slf4j
@Getter
@Component
public class KmsKeyMaterial {

    private KeyPair   signingKeyPair;
    private X509Certificate signingCertificate;
    private X509CertificateHolder signingCertHolder;

    @PostConstruct
    public void init() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        log.info("Generating RSA-2048 signing key pair for mock KMS...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        signingKeyPair = kpg.generateKeyPair();

        log.info("Issuing self-signed OCSP signing certificate...");
        signingCertHolder = buildSigningCert(signingKeyPair);
        signingCertificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(signingCertHolder);

        log.info("Mock KMS ready. signingCert.subject={} notAfter={}",
                signingCertHolder.getSubject(),
                signingCertHolder.getNotAfter());
    }

    /**
     * Rotates the signing key pair and certificate in-memory.
     * Simulates what the HSM / CA would do when the OCSP responder requests a renewal.
     * Thread-safe: synchronized so concurrent /renew calls are serialised.
     */
    public synchronized void rotate() throws Exception {
        log.info("Rotating OCSP signing key material...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        signingKeyPair = kpg.generateKeyPair();
        signingCertHolder = buildSigningCert(signingKeyPair);
        signingCertificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(signingCertHolder);
        log.info("OCSP signing cert rotated. new notAfter={}", signingCertHolder.getNotAfter());
    }

    // -------------------------------------------------------------------------

    private X509CertificateHolder buildSigningCert(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=Mock-OCSP-Signer, O=Company, C=FR");
        Instant now      = Instant.now();
        Instant notAfter = now.plus(90, ChronoUnit.DAYS);

        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
                keyPair.getPublic().getEncoded());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                subject,                                      // issuer (self-signed)
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(now),
                Date.from(notAfter),
                subject,                                      // subject
                spki
        );

        // EKU: id-kp-OCSPSigning
        builder.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));

        // OCSP No-Check (RFC 6960 §4.2.2.2.1 — signer cert doesn't need its own OCSP check)
        builder.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false,
                new DEROctetString(new byte[0]));

        // Not a CA
        builder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(false));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        return builder.build(signer);
    }
}
