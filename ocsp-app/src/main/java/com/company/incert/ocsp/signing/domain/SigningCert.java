package com.company.incert.ocsp.signing.domain;

import org.bouncycastle.cert.X509CertificateHolder;

import java.time.Instant;

/**
 * Immutable record representing the loaded OCSP signing certificate metadata.
 * Holds BC holder for use by the OcspSigner implementations.
 */
public record SigningCert(
    String keyLabel,
    String algorithm,
    X509CertificateHolder[] chain,   // [0] = signer cert, rest = intermediate CAs
    Instant notAfter
) {}

