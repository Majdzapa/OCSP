package com.company.ocsp.sync.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Response from the KMS active-signing-cert endpoint.
 *
 * @param keyReference   Opaque KMS key handle for the active OCSP signing key.
 * @param algorithm      Signing algorithm (e.g. "SHA256withRSA").
 * @param pemChain       Ordered list of PEM-encoded certificates: signer cert first,
 *                       then any intermediates, then the issuing CA.
 * @param notBefore      ISO-8601 validity start.
 * @param notAfter       ISO-8601 validity end.
 */
public record SigningCertResponse(
    @JsonProperty("keyReference") String       keyReference,
    @JsonProperty("algorithm")    String       algorithm,
    @JsonProperty("pemChain")     List<String> pemChain,
    @JsonProperty("notBefore")    String       notBefore,
    @JsonProperty("notAfter")     String       notAfter
) {}
