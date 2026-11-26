package lu.incert.ocsp.signing.pkcs11;

import java.util.List;

/**
 * Low-level Cryptoki (PKCS#11 v2.40) device port interface.
 */
public interface Pkcs11LibraryPort extends AutoCloseable {

    String getLibraryPath();

    long cInitialize(long flags);

    long cFinalize();

    long[] cGetSlotList(boolean tokenPresent);

    TokenInfo cGetTokenInfo(long slotId);

    /**
     * Queries the HSM slot's supported PKCS#11 mechanism codes via {@code C_GetMechanismList}.
     */
    default long[] cGetMechanismList(long slotId) {
        return new long[]{
                Pkcs11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN,
                Pkcs11Constants.CKM_EC_KEY_PAIR_GEN,
                Pkcs11Constants.CKM_RSA_PKCS,
                Pkcs11Constants.CKM_SHA256_RSA_PKCS,
                Pkcs11Constants.CKM_SHA384_RSA_PKCS,
                Pkcs11Constants.CKM_SHA512_RSA_PKCS,
                Pkcs11Constants.CKM_SHA256_RSA_PKCS_PSS,
                Pkcs11Constants.CKM_SHA384_RSA_PKCS_PSS,
                Pkcs11Constants.CKM_SHA512_RSA_PKCS_PSS,
                Pkcs11Constants.CKM_ECDSA
        };
    }

    /**
     * Queries key-size range and capability flags for a mechanism on a slot via {@code C_GetMechanismInfo}.
     */
    default MechanismInfo cGetMechanismInfo(long slotId, long mechanismType) {
        return new MechanismInfo(
                mechanismType,
                0L,
                Long.MAX_VALUE,
                Pkcs11Constants.CKF_SIGN | Pkcs11Constants.CKF_GENERATE_KEY_PAIR
        );
    }

    long cOpenSession(long slotId, long flags);

    void cCloseSession(long sessionHandle);

    void cCloseAllSessions(long slotId);

    long cLogin(long sessionHandle, long userType, char[] pin);

    long cLogout(long sessionHandle);

    void cFindObjectsInit(long sessionHandle, List<Pkcs11Attribute> template);

    long[] cFindObjects(long sessionHandle, int maxCount);

    void cFindObjectsFinal(long sessionHandle);

    byte[] cGetAttributeValue(long sessionHandle, long objectHandle, long attrType);

    long cGetAttributeUlong(long sessionHandle, long objectHandle, long attrType);

    long[] cGenerateKeyPair(
            long sessionHandle,
            Pkcs11Mechanism mechanism,
            List<Pkcs11Attribute> publicKeyTemplate,
            List<Pkcs11Attribute> privateKeyTemplate
    );

    long cCreateObject(long sessionHandle, List<Pkcs11Attribute> template);

    void cSignInit(long sessionHandle, Pkcs11Mechanism mechanism, long keyHandle);

    byte[] cSign(long sessionHandle, byte[] data);

    @Override
    void close();
}

