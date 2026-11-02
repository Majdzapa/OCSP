package com.company.ocsp.sync.client;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response from the KMS sign endpoint.
 *
 * @param signature Base64-encoded DER-formatted signature bytes.
 *                  Decode with {@code Base64.getDecoder().decode(signature)}.
 */
public record SignResponse(
    @JsonProperty("signature") String signature
) {}
