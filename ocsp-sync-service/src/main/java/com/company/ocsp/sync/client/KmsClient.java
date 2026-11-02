package com.company.ocsp.sync.client;

import org.springframework.http.MediaType;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

/**
 * Declarative Spring HTTP Interface for the internal KMS.
 *
 * <p>Two operations are required:
 * <ol>
 *   <li>{@link #sign(SignRequest)} — called by the responder's
 *       {@code KmsBackedContentSigner} to sign OCSP TBS bytes.</li>
 *   <li>{@link #reconcile()} — called hourly by the reconciliation job to
 *       compare the KMS's authoritative revocation count with the local DB.</li>
 * </ol>
 *
 * <p>All requests are made over TLS 1.3 with mutual authentication
 * (client certificate in PKCS12 keystore, server CA in truststore).
 * The underlying {@code RestClient} is configured in {@code KmsClientConfig}.
 *
 * @see KmsClientConfig
 */
// Base URL is set on the RestClient in KmsClientConfig (kms.base-url).
// Do not put "${...}" here: HttpServiceProxyFactory treats it as a URI template variable.
@HttpExchange(
    contentType     = MediaType.APPLICATION_JSON_VALUE,
    accept          = MediaType.APPLICATION_JSON_VALUE
)
public interface KmsClient {

    /**
     * Sign a TBS (to-be-signed) byte array using the KMS-held private key.
     *
     * @param request contains the opaque key reference, base64-encoded TBS bytes,
     *                and the signing algorithm name (e.g. "SHA256withRSA")
     * @return {@link SignResponse} carrying the base64-encoded DER signature
     */
    @PostExchange("/api/v1/kms/sign")
    SignResponse sign(SignRequest request);

    /**
     * Returns the total number of revoked certificates known to the KMS.
     * Used by the reconciliation job to detect local DB drift.
     *
     * @return {@link ReconciliationResponse} with the authoritative revoked count
     */
    @GetExchange("/api/v1/kms/reconciliation")
    ReconciliationResponse reconcile();

    /**
     * Returns the active OCSP signing certificate metadata including its
     * PEM-encoded chain and KMS key reference.
     *
     * @return {@link SigningCertResponse} with chain + key reference
     */
    @GetExchange("/api/v1/kms/ocsp/signing-cert/active")
    SigningCertResponse getActiveSigningCert();
}
