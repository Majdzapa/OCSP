package com.company.incert.pkcs11j.nativebridge;

/**
 * Direct JNI entry points into {@code pkcs11j_jni.c}.
 */
public final class Pkcs11NativeBridge {

    static {
        NativeLibraryLoader.ensureLoaded();
    }

    private Pkcs11NativeBridge() {}

    public static native long loadModule(String libraryPath);

    public static native void unloadModule(long moduleHandle);

    public static native long cInitialize(long moduleHandle, long flags);

    public static native long cFinalize(long moduleHandle);

    public static native long[] cGetSlotList(long moduleHandle, boolean tokenPresent);

    public static native String[] cGetTokenInfo(long moduleHandle, long slotId);

    public static native long cOpenSession(long moduleHandle, long slotId, long flags);

    public static native void cCloseSession(long moduleHandle, long sessionHandle);

    public static native void cCloseAllSessions(long moduleHandle, long slotId);

    public static native long cLogin(long moduleHandle, long sessionHandle, long userType, byte[] pin);

    public static native long cLogout(long moduleHandle, long sessionHandle);

    public static native void cFindObjectsInit(
            long moduleHandle,
            long sessionHandle,
            long[] attrTypes,
            int[] attrKinds,
            long[] longVals,
            byte[][] byteVals
    );

    public static native long[] cFindObjects(long moduleHandle, long sessionHandle, int maxCount);

    public static native void cFindObjectsFinal(long moduleHandle, long sessionHandle);

    public static native byte[] cGetAttributeValue(long moduleHandle, long sessionHandle, long objectHandle, long attrType);

    public static native long cGetAttributeUlong(long moduleHandle, long sessionHandle, long objectHandle, long attrType);

    public static native long[] cGenerateKeyPair(
            long moduleHandle,
            long sessionHandle,
            long mechanismType,
            long[] pubTypes,
            int[] pubKinds,
            long[] pubLongs,
            byte[][] pubBytes,
            long[] privTypes,
            int[] privKinds,
            long[] privLongs,
            byte[][] privBytes
    );

    public static native long cCreateObject(
            long moduleHandle,
            long sessionHandle,
            long[] attrTypes,
            int[] attrKinds,
            long[] longVals,
            byte[][] byteVals
    );

    public static native void cSignInit(
            long moduleHandle,
            long sessionHandle,
            long mechanismType,
            boolean isPss,
            long pssHashAlg,
            long pssMgf,
            long pssSaltLen,
            long keyHandle
    );

    public static native byte[] cSign(long moduleHandle, long sessionHandle, byte[] data);
}

