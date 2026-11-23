package com.company.incert.ocsp.signing.hsm;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.operator.ContentSigner;

/**
 * Focused hot-path OCSP response signing contract (Interface Segregation Principle).
 * Used by responders and metrics without exposing administrative keygen/CSR operations.
 */
public interface OcspResponseSigner {

    ContentSigner createContentSigner() throws Exception;

    X509CertificateHolder[] getSignerChain();

    long signingCertDaysUntilExpiry();

    String type();

    default SigningSelection selectSigner(CertificateID certId) throws Exception {
        return new SigningSelection(getSignerChain(), createContentSigner());
    }

    record SigningSelection(X509CertificateHolder[] chain, ContentSigner contentSigner) {}
}

