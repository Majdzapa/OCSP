package com.company.ocsp.responder.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.http.MediaType;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;
import org.springframework.web.service.annotation.PostExchange;

import java.util.List;

/**
 * Declarative Spring HTTP Interface for the KMS, used by the OCSP responder.
 *
 * <p>The responder only needs two operations:
 * <ol>
 *   <li>{@link #sign(SignRequest)} — sign the OCSP TBS bytes (called per response).</li>
 *   <li>{@link #getActiveSigningCert()} — fetch the current OCSP signing certificate
 *       chain and key reference (called at startup and on cert rotation).</li>
 * </ol>
 *
 * <p>All calls are made over TLS 1.3 / mTLS.  The underlying {@code RestClient}
 * is configured in {@link KmsClientConfig}.
 */
// Base URL is set on the RestClient in KmsClientConfig (kms.base-url).
// Do not put "${...}" here: HttpServiceProxyFactory treats it as a URI template variable.
@HttpExchange(
    contentType = MediaType.APPLICATION_JSON_VALUE,
    accept      = MediaType.APPLICATION_JSON_VALUE
)
public interface KmsHttpClient {

    /** Sign the supplied TBS bytes using the KMS-held private key. */
    @PostExchange("/api/v1/kms/sign")
    SignResponse sign(SignRequest request);

    /** Fetch the active OCSP delegated signing certificate chain + key reference. */
    @GetExchange("/api/v1/kms/ocsp/signing-cert/active")
    SigningCertResponse getActiveSigningCert();

    // ---- Nested DTOs --------------------------------------------------------

    record SignRequest(
        @JsonProperty("keyReference") String keyReference,
        @JsonProperty("tbsBytes")     String tbsBytes,   // base64
        @JsonProperty("algorithm")    String algorithm
    ) {}

    record SignResponse(
        @JsonProperty("signature") String signature      // base64 DER
    ) {}

    record SigningCertResponse(
        @JsonProperty("keyReference") String       keyReference,
        @JsonProperty("algorithm")    String       algorithm,
        @JsonProperty("pemChain")     List<String> pemChain,
        @JsonProperty("notBefore")    String       notBefore,
        @JsonProperty("notAfter")     String       notAfter
    ) {}
}
