package com.company.incert.ocsp.signing;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;

/**
 * Signs OCSP responses.
 * Implementations: {@link Pkcs11OcspSigner} (SoftHSM2 / real HSM) and
 * {@link SoftwareKeyOcspSigner} (in-memory key, dev/test fallback only).
 */
public interface OcspSigner {

    /** Create a new ContentSigner instance (not reusable across calls). */
    ContentSigner createContentSigner() throws Exception;

    /** Certificate chain to embed in OCSP responses. [0] = signer cert. */
    X509CertificateHolder[] getSignerChain();

    /** Days until signing certificate expires (for metrics/alerting). */
    long signingCertDaysUntilExpiry();

    /** Human-readable signer type, e.g. "PKCS11" or "SOFTWARE". */
    String type();
}

