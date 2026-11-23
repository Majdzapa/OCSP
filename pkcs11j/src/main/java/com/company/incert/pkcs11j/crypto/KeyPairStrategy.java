package com.company.incert.pkcs11j.crypto;

import com.company.incert.pkcs11j.port.Pkcs11LibraryPort;

/**
 * Open-Closed strategy for generating an asymmetric keypair on a PKCS#11 token.
 * Register additional implementations in {@link KeyPairStrategies} without editing {@code Pkcs11Provider}.
 */
public interface KeyPairStrategy {

    boolean supports(String keyAlgorithm);

    String defaultSignatureAlgorithm();

    /**
     * Generates a non-extractable token keypair via {@code C_GenerateKeyPair}.
     *
     * @return 2-element array {@code [publicKeyHandle, privateKeyHandle]}
     */
    long[] generate(Pkcs11LibraryPort library, long session, String keyLabel, byte[] keyId, int keySize);
}

