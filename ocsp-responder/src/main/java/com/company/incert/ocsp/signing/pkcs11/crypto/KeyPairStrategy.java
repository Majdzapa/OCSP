package com.company.incert.ocsp.signing.pkcs11.crypto;

import com.company.incert.ocsp.signing.pkcs11.Pkcs11LibraryPort;

/**
 * Open-Closed strategy for generating an asymmetric keypair on a PKCS#11 token.
 */
public interface KeyPairStrategy {

    boolean supports(String keyAlgorithm);

    String defaultSignatureAlgorithm();

    long[] generate(Pkcs11LibraryPort library, long session, String keyLabel, byte[] keyId, int keySize);
}

