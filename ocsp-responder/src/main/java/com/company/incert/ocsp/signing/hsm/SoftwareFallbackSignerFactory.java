package com.company.incert.ocsp.signing.hsm;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Factory building the in-memory RSA fallback {@link OcspSigner} for non-production environments
 * when {@code hsm.enabled=false}.
 */
public final class SoftwareFallbackSignerFactory {

    private SoftwareFallbackSignerFactory() {}

    public static SoftwareKeyOcspSigner create() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            X500Name name = new X500Name("CN=Incert Delegated OCSP Signer (Fallback),O=Incert,C=CH");
            BigInteger serial = new BigInteger(63, new SecureRandom());
            Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
            Date notAfter = Date.from(Instant.now().plus(30, ChronoUnit.DAYS));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate());
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                    name, serial, notBefore, notAfter, name,
                    SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
            );
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));

            X509CertificateHolder holder = builder.build(signer);
            return new SoftwareKeyOcspSigner(kp.getPrivate(), new X509CertificateHolder[]{holder}, notAfter.toInstant());
        } catch (Exception e) {
            throw new IllegalStateException("Could not create fallback signer", e);
        }
    }
}

