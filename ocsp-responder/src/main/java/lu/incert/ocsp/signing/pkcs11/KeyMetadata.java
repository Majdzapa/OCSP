package lu.incert.ocsp.signing.pkcs11;

/**
 * Metadata for a signing private key stored inside a PKCS#11 token.
 */
public record KeyMetadata(
        String keyLabel,
        String keyAlgorithm,
        int keySizeBits,
        long privateKeyHandle
) {}

