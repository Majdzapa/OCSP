package com.company.incert.pkcs11j;

/**
 * PKCS#11 CK_MECHANISM descriptor supporting both parameterless mechanisms
 * and CK_RSA_PKCS_PSS_PARAMS.
 */
public record Pkcs11Mechanism(
        long mechanismType,
        boolean pss,
        long pssHashAlg,
        long pssMgf,
        long pssSaltLen
) {
    public static Pkcs11Mechanism of(long mechanismType) {
        return new Pkcs11Mechanism(mechanismType, false, 0L, 0L, 0L);
    }

    public static Pkcs11Mechanism rsaPssSha256() {
        return new Pkcs11Mechanism(
                Pkcs11Constants.CKM_SHA256_RSA_PKCS_PSS,
                true,
                Pkcs11Constants.CKM_SHA256,
                Pkcs11Constants.CKG_MGF1_SHA256,
                32L
        );
    }

    public static Pkcs11Mechanism rsaPssRawSha256() {
        return new Pkcs11Mechanism(
                Pkcs11Constants.CKM_RSA_PKCS_PSS,
                true,
                Pkcs11Constants.CKM_SHA256,
                Pkcs11Constants.CKG_MGF1_SHA256,
                32L
        );
    }
}

