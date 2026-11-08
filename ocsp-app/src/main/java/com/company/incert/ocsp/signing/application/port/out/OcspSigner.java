package com.company.incert.ocsp.signing.application.port.out;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;

/**
 * Driven port: produce a ContentSigner and provide signing certificate metadata.
 * Implementations: Pkcs11OcspSigner (production), SoftwareKeyOcspSigner (test).
 */
public interface OcspSigner {
    /** Create a new ContentSigner instance (not reusable across calls). */
    ContentSigner createContentSigner() throws Exception;

    /** Certificate chain to embed in OCSP responses. [0] = signer cert. */
    X509CertificateHolder[] getSignerChain();

    /** Days until signing certificate expires (for metrics/alerting). */
    long signingCertDaysUntilExpiry();
}
