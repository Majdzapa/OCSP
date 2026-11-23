package com.company.incert.pkcs11j.crypto;

import com.company.incert.pkcs11j.port.Pkcs11LibraryPort;

/**
 * Open-Closed strategy for signing data with a private key handle inside a PKCS#11 token.
 */
public interface SignatureStrategy {

    boolean supports(String signatureAlgorithm);

    byte[] sign(
            Pkcs11LibraryPort library,
            long session,
            long keyHandle,
            String signatureAlgorithm,
            byte[] data,
            boolean prehashInJvm
    );
}

