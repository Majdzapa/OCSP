package com.company.incert.ocsp.signing.pkcs11.crypto;

import com.company.incert.ocsp.signing.pkcs11.Pkcs11LibraryPort;
import com.company.incert.ocsp.signing.pkcs11.Pkcs11Mechanism;

/**
 * RSA-PSS signing strategy ({@code SHA256withRSAandMGF1}) using {@code CKM_SHA256_RSA_PKCS_PSS}.
 */
public final class RsaPssSignatureStrategy implements SignatureStrategy {

    @Override
    public boolean supports(String signatureAlgorithm) {
        return "SHA256withRSAandMGF1".equalsIgnoreCase(signatureAlgorithm);
    }

    @Override
    public byte[] sign(
            Pkcs11LibraryPort library,
            long session,
            long keyHandle,
            String signatureAlgorithm,
            byte[] data,
            boolean prehashInJvm) {
        library.cSignInit(session, Pkcs11Mechanism.rsaPssSha256(), keyHandle);
        return library.cSign(session, data);
    }
}

