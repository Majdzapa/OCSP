package com.company.ocsp.sync.client;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Request payload for the KMS sign endpoint.
 *
 * @param keyReference  Opaque KMS key handle (e.g. "ocsp-signing-key-01").
 *                      Must match the active OCSP signing key.
 * @param tbsBytes      Base64-encoded DER bytes of the to-be-signed content.
 * @param algorithm     Signing algorithm name understood by the KMS
 *                      (e.g. "SHA256withRSA", "SHA384withECDSA").
 */
public record SignRequest(
    @JsonProperty("keyReference") String keyReference,
    @JsonProperty("tbsBytes")     String tbsBytes,
    @JsonProperty("algorithm")    String algorithm
) {}
