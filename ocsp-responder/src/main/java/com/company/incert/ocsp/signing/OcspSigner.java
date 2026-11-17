package com.company.incert.ocsp.signing;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.operator.ContentSigner;

import java.util.List;

/**
 * Cryptographic HSM signing adapter interface for OCSP responses.
 *
 * Decouples OCSP response signing from specific cryptographic hardware or cloud HSM providers.
 *
 * Current implementations / adapters:
 * <ul>
 *   <li>{@link Pkcs11OcspSigner}: Hardware Security Module (HSM) / SoftHSM2 adapter using PKCS#11</li>
 *   <li>{@link SoftwareKeyOcspSigner}: In-memory software key adapter (dev/test fallback only)</li>
 * </ul>
 */
public interface OcspSigner {

    /** Create a new ContentSigner instance (not reusable across concurrent calls). */
    ContentSigner createContentSigner() throws Exception;

    /** Certificate chain to embed in OCSP responses. Index 0 is the signer certificate. */
    X509CertificateHolder[] getSignerChain();

    /** Days until the signing certificate expires (for metrics and alerting). */
    long signingCertDaysUntilExpiry();

    /** Human-readable signer/adapter type, e.g. "PKCS11", "SOFTWARE", "AWS_KMS", "AZURE_KV". */
    String type();

    /**
     * Dynamically updates the active signing certificate and associated key label in the HSM/keystore.
     * Takes effect immediately for subsequent signing calls without restarting the service.
     */
    default void updateActiveCertificate(String keyLabel, X509CertificateHolder certificate) {}

    /**
     * Dynamically updates the active signing certificate, key label, and signature algorithm.
     */
    default void updateActiveCertificate(String keyLabel, X509CertificateHolder certificate, String signatureAlgorithm) {
        updateActiveCertificate(keyLabel, certificate);
    }

    /** Returns the key label / alias currently active for signing. */
    default String getActiveKeyLabel() {
        return "ocsp-signing-key";
    }

    /** Returns all key aliases/labels currently stored in the HSM token. */
    default List<String> listKeyLabels() {
        return List.of(getActiveKeyLabel());
    }

    /**
     * Generates (or reuses) a keypair inside the HSM and returns a PEM-encoded PKCS#10 CSR.
     */
    default String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
        throw new UnsupportedOperationException("CSR generation is only supported when PKCS#11 HSM is enabled");
    }

    /**
     * Imports a CA-signed X.509 certificate into the HSM token for the given key label.
     */
    default void importCertificateToToken(String keyLabel, X509CertificateHolder certificate) {}

    /**
     * Synchronizes the full list of non-expired registered signing certificates
     * so the signer can automatically select the matching CA's signing certificate per request.
     */
    default void syncRegisteredSigners(List<RegisteredSigner> signers) {}

    /**
     * Selects the appropriate signing certificate chain and ContentSigner for the given OCSP CertID
     * (matching the issuing CA), falling back to the default active signer if no CA-specific match exists.
     */
    default SigningSelection selectSigner(CertificateID certId) throws Exception {
        return new SigningSelection(getSignerChain(), createContentSigner());
    }

    record RegisteredSigner(String keyLabel, X509CertificateHolder certificate, boolean preferred, String signatureAlgorithm) {
        public RegisteredSigner(String keyLabel, X509CertificateHolder certificate, boolean preferred) {
            this(keyLabel, certificate, preferred, null);
        }
    }

    record SigningSelection(X509CertificateHolder[] chain, ContentSigner contentSigner) {}
}
