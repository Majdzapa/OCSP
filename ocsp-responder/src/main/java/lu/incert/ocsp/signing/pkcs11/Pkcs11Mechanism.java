package lu.incert.ocsp.signing.pkcs11;

/**
 * PKCS#11 {@code CK_MECHANISM} descriptor supporting parameterless mechanisms and {@code CK_RSA_PKCS_PSS_PARAMS}.
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

    public static Pkcs11Mechanism rsaPssSha384() {
        return new Pkcs11Mechanism(
                Pkcs11Constants.CKM_SHA384_RSA_PKCS_PSS,
                true,
                Pkcs11Constants.CKM_SHA384,
                Pkcs11Constants.CKG_MGF1_SHA384,
                48L
        );
    }

    public static Pkcs11Mechanism rsaPssSha512() {
        return new Pkcs11Mechanism(
                Pkcs11Constants.CKM_SHA512_RSA_PKCS_PSS,
                true,
                Pkcs11Constants.CKM_SHA512,
                Pkcs11Constants.CKG_MGF1_SHA512,
                64L
        );
    }
}

