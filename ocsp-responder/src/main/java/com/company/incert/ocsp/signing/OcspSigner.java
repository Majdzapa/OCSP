package com.company.incert.ocsp.signing;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;

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
 *
 * To connect to a different HSM (e.g. AWS CloudHSM, Azure Key Vault, HashiCorp Vault,
 * or Thales Luna), simply implement this interface as an adapter and register it as an
 * {@link OcspSigner} bean. The rest of the application remains completely untouched.
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
}
