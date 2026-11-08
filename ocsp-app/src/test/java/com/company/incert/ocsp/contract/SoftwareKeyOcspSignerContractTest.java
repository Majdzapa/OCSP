package com.company.incert.ocsp.contract;

import com.company.incert.ocsp.signing.adapter.out.SoftwareKeyOcspSigner;
import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class SoftwareKeyOcspSignerContractTest extends OcspSignerContract {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    protected OcspSigner createSigner() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X500Name name = new X500Name("CN=Contract Test Signer,O=Incert,C=CH");
        Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(30, ChronoUnit.DAYS));

        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            name, BigInteger.valueOf(999), notBefore, notAfter, name,
            SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
        );
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        X509CertificateHolder holder = builder.build(cs);

        return new SoftwareKeyOcspSigner(kp.getPrivate(), new X509CertificateHolder[]{holder}, notAfter.toInstant());
    }
}

