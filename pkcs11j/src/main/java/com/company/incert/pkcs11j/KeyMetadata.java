package com.company.incert.pkcs11j;

/**
 * Metadata for a signing private key stored inside a PKCS#11 token.
 */
public record KeyMetadata(
        String keyLabel,
        String keyAlgorithm,
        int keySizeBits,
        long privateKeyHandle
) {}

