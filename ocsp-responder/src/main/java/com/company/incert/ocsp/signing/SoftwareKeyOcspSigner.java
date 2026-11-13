package com.company.incert.ocsp.signing;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.PrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Software-key OcspSigner for unit tests and dev fallback only.
 * Uses an in-memory PrivateKey — NEVER for production.
 */
public class SoftwareKeyOcspSigner implements OcspSigner {

    private final PrivateKey privateKey;
    private final AtomicReference<SignerState> stateRef = new AtomicReference<>();
    private volatile String activeKeyLabel = "software-key";

    public SoftwareKeyOcspSigner(PrivateKey privateKey, X509CertificateHolder[] chain, Instant certExpiry) {
        this.privateKey = privateKey;
        this.stateRef.set(new SignerState(chain, certExpiry));
    }

    @Override
    public ContentSigner createContentSigner() throws Exception {
        return new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(privateKey);
    }

    @Override
    public X509CertificateHolder[] getSignerChain() {
        return stateRef.get().chain();
    }

    @Override
    public long signingCertDaysUntilExpiry() {
        return ChronoUnit.DAYS.between(Instant.now(), stateRef.get().certExpiry());
    }

    @Override
    public String type() {
        return "SOFTWARE";
    }

    @Override
    public void updateActiveCertificate(String keyLabel, X509CertificateHolder certificate) {
        if (keyLabel != null && !keyLabel.isBlank()) {
            this.activeKeyLabel = keyLabel;
        }
        if (certificate != null) {
            this.stateRef.set(new SignerState(new X509CertificateHolder[]{certificate}, certificate.getNotAfter().toInstant()));
        }
    }

    @Override
    public String getActiveKeyLabel() {
        return this.activeKeyLabel;
    }

    private record SignerState(X509CertificateHolder[] chain, Instant certExpiry) {}
}
