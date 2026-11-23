package com.company.incert.pkcs11j.port;

import com.company.incert.pkcs11j.Pkcs11Attribute;
import com.company.incert.pkcs11j.Pkcs11Mechanism;
import com.company.incert.pkcs11j.TokenInfo;

import java.util.List;

/**
 * Low-level Cryptoki (PKCS#11 v2.40) device port interface.
 * Maps 1:1 to C_Initialize, C_GetSlotList, C_OpenSession, C_Login, C_FindObjects*,
 * C_GetAttributeValue, C_GenerateKeyPair, C_CreateObject, C_SignInit, C_Sign, C_Logout, C_Finalize.
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

    /**
     * Generates an asymmetric key pair inside the token.
     *
     * @return 2-element array [publicKeyHandle, privateKeyHandle]
     */
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

