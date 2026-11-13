package com.company.incert.ocsp.config;

import com.company.incert.ocsp.signing.OcspSigner;
import com.company.incert.ocsp.signing.Pkcs11OcspSigner;
import com.company.incert.ocsp.signing.SoftwareKeyOcspSigner;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Chooses the OCSP signer: PKCS#11 (SoftHSM2) by default, with an in-memory
 * software key as fallback when the token is unavailable (dev/test only).
 */
@Slf4j
@Configuration
public class SigningConfig {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Value("${hsm.pkcs11-library:/usr/lib/softhsm/libsofthsm2.so}")
    private String pkcs11Library;

    @Value("${hsm.token-label:ocsp-signing}")
    private String tokenLabel;

    @Value("${hsm.pin:1234}")
    private String pin;

    @Value("${hsm.key-label:ocsp-signing-key}")
    private String keyLabel;

    @Bean
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true", matchIfMissing = true)
    public OcspSigner pkcs11OcspSigner() {
        try {
            log.info("Attempting to initialize PKCS#11 signer from library: {}", pkcs11Library);
            return new Pkcs11OcspSigner(pkcs11Library, tokenLabel, pin, keyLabel);
        } catch (Exception e) {
            log.warn("PKCS#11 initialization failed ({}). Falling back to software signer for dev/test.", e.getMessage());
            return createFallbackSoftwareSigner();
        }
    }

    @Bean
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "false")
    public OcspSigner softwareSigner() {
        log.info("HSM disabled by configuration; using software signer.");
        return createFallbackSoftwareSigner();
    }

    private SoftwareKeyOcspSigner createFallbackSoftwareSigner() {
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

