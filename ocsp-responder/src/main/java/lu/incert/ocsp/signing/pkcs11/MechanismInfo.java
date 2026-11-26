package lu.incert.ocsp.signing.pkcs11;

/**
 * Snapshot of PKCS#11 {@code CK_MECHANISM_INFO} queried from an HSM slot via {@code C_GetMechanismInfo}.
 */
public record MechanismInfo(
        long mechanismCode,
        long minKeySize,
        long maxKeySize,
        long flags
) {
    public boolean supportsSign() {
        return (flags & Pkcs11Constants.CKF_SIGN) != 0L;
    }

    public boolean supportsKeyPairGen() {
        return (flags & Pkcs11Constants.CKF_GENERATE_KEY_PAIR) != 0L;
    }

    public boolean isHardware() {
        return (flags & Pkcs11Constants.CKF_HW) != 0L;
    }

    public boolean supportsKeySize(int keySizeBits) {
        if (keySizeBits <= 0) {
            return false;
        }
        boolean aboveMin = minKeySize <= 0 || keySizeBits >= minKeySize;
        boolean belowMax = maxKeySize <= 0 || keySizeBits <= maxKeySize;
        return aboveMin && belowMax;
    }
}

