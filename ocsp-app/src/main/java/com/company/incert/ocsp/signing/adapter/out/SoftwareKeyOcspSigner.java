package com.company.incert.ocsp.signing.adapter.out;

import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.PrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Software-key OcspSigner adapter for unit and integration tests only.
 * Uses an in-memory PrivateKey — NEVER for production.
 */
@RequiredArgsConstructor
public class SoftwareKeyOcspSigner implements OcspSigner {

    private final PrivateKey privateKey;
    private final X509CertificateHolder[] chain;
    private final Instant certExpiry;

    @Override
    public ContentSigner createContentSigner() throws Exception {
        return new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(privateKey);
    }

    @Override
    public X509CertificateHolder[] getSignerChain() {
        return chain;
    }

    @Override
    public long signingCertDaysUntilExpiry() {
        return ChronoUnit.DAYS.between(Instant.now(), certExpiry);
    }
}

