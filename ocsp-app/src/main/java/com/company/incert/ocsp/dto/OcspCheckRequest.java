package com.company.incert.ocsp.dto;

/**
 * Input for the OCSP client.
 * <p>
 * Identify the certificate in one of these ways:
 * <ul>
 *   <li>{@code certificatePem} + {@code issuerPem} — standard client usage (like {@code openssl ocsp -cert -issuer})</li>
 *   <li>{@code serialHex} + {@code issuerPem} — when only the serial is known</li>
 *   <li>{@code serialHex} only — issuer hashes are taken from the local status table (console convenience)</li>
 * </ul>
 *
 * @param includeNonce  add an RFC 8954 nonce (32 random octets) and require it to be echoed
 * @param method        "POST" (default) or "GET"
 * @param responderUrl  optional; defaults to {@code ocsp.client.default-responder-url}
 */
public record OcspCheckRequest(
    String serialHex,
    String certificatePem,
    String issuerPem,
    boolean includeNonce,
    String method,
    String responderUrl
) {}

