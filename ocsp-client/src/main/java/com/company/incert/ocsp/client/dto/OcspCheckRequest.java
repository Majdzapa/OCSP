package com.company.incert.ocsp.client.dto;

/**
 * Input for the OCSP client check request.
 *
 * @param serialHex     target certificate serial number in hex
 * @param certificatePem target certificate in PEM format (optional)
 * @param issuerPem     issuer / CA certificate in PEM format (optional)
 * @param includeNonce  whether to include the RFC 6960 / RFC 8954 Nonce extension
 * @param method        HTTP method: "POST" (DER binary) or "GET" (base64url)
 * @param responderUrl  OCSP responder URL (e.g. http://localhost:8080/ocsp)
 */
public record OcspCheckRequest(
    String serialHex,
    String certificatePem,
    String issuerPem,
    boolean includeNonce,
    String method,
    String responderUrl
) {}
