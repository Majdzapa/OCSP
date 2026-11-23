package com.company.incert.ocsp.signing.pkcs11;

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

