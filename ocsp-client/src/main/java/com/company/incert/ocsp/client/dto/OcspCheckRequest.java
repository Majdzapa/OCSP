package com.company.incert.ocsp.client.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Input for the OCSP client check request.
 */
@Schema(description = "Parameters for executing an RFC 6960 OCSP validation check against a responder")
public record OcspCheckRequest(
    @Schema(description = "Target certificate serial number in hex", example = "00b59d41baf78afe0de1bbe7ae28c0450f")
    String serialHex,
    @Schema(description = "Target certificate in PEM format (optional)")
    String certificatePem,
    @Schema(description = "Issuer / CA certificate in PEM format (optional)")
    String issuerPem,
    @Schema(description = "Whether to include the RFC 6960 / RFC 8954 Nonce extension in the request", example = "true")
    boolean includeNonce,
    @Schema(description = "HTTP Transport Method: POST (DER binary) or GET (base64url)", example = "POST")
    String method,
    @Schema(description = "OCSP responder URL endpoint", example = "http://localhost:8080/ocsp")
    String responderUrl
) {}


