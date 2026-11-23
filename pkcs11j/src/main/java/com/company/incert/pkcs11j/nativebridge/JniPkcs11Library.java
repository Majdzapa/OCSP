package com.company.incert.pkcs11j.nativebridge;

import com.company.incert.pkcs11j.Pkcs11Attribute;
import com.company.incert.pkcs11j.Pkcs11Mechanism;
import com.company.incert.pkcs11j.TokenInfo;
import com.company.incert.pkcs11j.port.Pkcs11LibraryPort;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@link Pkcs11LibraryPort} implementation backed by the custom C JNI bridge ({@link Pkcs11NativeBridge}).
 */
public final class JniPkcs11Library implements Pkcs11LibraryPort {

    private final String libraryPath;
    private final AtomicLong moduleHandle;

    public JniPkcs11Library(String libraryPath) {
        if (libraryPath == null || libraryPath.isBlank()) {
            throw new IllegalArgumentException("PKCS#11 library path must not be blank");
        }
        this.libraryPath = libraryPath.trim();
        this.moduleHandle = new AtomicLong(Pkcs11NativeBridge.loadModule(this.libraryPath));
    }

    @Override
    public String getLibraryPath() {
        return libraryPath;
    }

    @Override
    public long cInitialize(long flags) {
        return Pkcs11NativeBridge.cInitialize(requireHandle(), flags);
    }

    @Override
    public long cFinalize() {
        return Pkcs11NativeBridge.cFinalize(requireHandle());
    }

    @Override
    public long[] cGetSlotList(boolean tokenPresent) {
        return Pkcs11NativeBridge.cGetSlotList(requireHandle(), tokenPresent);
    }

    @Override
    public TokenInfo cGetTokenInfo(long slotId) {
        String[] fields = Pkcs11NativeBridge.cGetTokenInfo(requireHandle(), slotId);
        long flags = fields.length > 4 && fields[4] != null ? Long.parseLong(fields[4]) : 0L;
        return new TokenInfo(slotId, fields[0], fields[1], fields[2], fields[3], flags);
    }

    @Override
    public long cOpenSession(long slotId, long flags) {
        return Pkcs11NativeBridge.cOpenSession(requireHandle(), slotId, flags);
    }

    @Override
    public void cCloseSession(long sessionHandle) {
        Pkcs11NativeBridge.cCloseSession(requireHandle(), sessionHandle);
    }

    @Override
    public void cCloseAllSessions(long slotId) {
        Pkcs11NativeBridge.cCloseAllSessions(requireHandle(), slotId);
    }

    @Override
    public long cLogin(long sessionHandle, long userType, char[] pin) {
        byte[] pinBytes = toUtf8Bytes(pin);
        try {
            return Pkcs11NativeBridge.cLogin(requireHandle(), sessionHandle, userType, pinBytes);
        } finally {
            Arrays.fill(pinBytes, (byte) 0);
        }
    }

    @Override
    public long cLogout(long sessionHandle) {
        return Pkcs11NativeBridge.cLogout(requireHandle(), sessionHandle);
    }

    @Override
    public void cFindObjectsInit(long sessionHandle, List<Pkcs11Attribute> template) {
        PackedTemplate packed = PackedTemplate.from(template);
        Pkcs11NativeBridge.cFindObjectsInit(
                requireHandle(), sessionHandle,
                packed.types(), packed.kinds(), packed.longs(), packed.bytes());
    }

    @Override
    public long[] cFindObjects(long sessionHandle, int maxCount) {
        return Pkcs11NativeBridge.cFindObjects(requireHandle(), sessionHandle, maxCount);
    }

    @Override
    public void cFindObjectsFinal(long sessionHandle) {
        Pkcs11NativeBridge.cFindObjectsFinal(requireHandle(), sessionHandle);
    }

    @Override
    public byte[] cGetAttributeValue(long sessionHandle, long objectHandle, long attrType) {
        return Pkcs11NativeBridge.cGetAttributeValue(requireHandle(), sessionHandle, objectHandle, attrType);
    }

    @Override
    public long cGetAttributeUlong(long sessionHandle, long objectHandle, long attrType) {
        return Pkcs11NativeBridge.cGetAttributeUlong(requireHandle(), sessionHandle, objectHandle, attrType);
    }

    @Override
    public long[] cGenerateKeyPair(
            long sessionHandle,
            Pkcs11Mechanism mechanism,
            List<Pkcs11Attribute> publicKeyTemplate,
            List<Pkcs11Attribute> privateKeyTemplate) {
        PackedTemplate pub = PackedTemplate.from(publicKeyTemplate);
        PackedTemplate priv = PackedTemplate.from(privateKeyTemplate);
        return Pkcs11NativeBridge.cGenerateKeyPair(
                requireHandle(),
                sessionHandle,
                mechanism.mechanismType(),
                pub.types(), pub.kinds(), pub.longs(), pub.bytes(),
                priv.types(), priv.kinds(), priv.longs(), priv.bytes());
    }

    @Override
    public long cCreateObject(long sessionHandle, List<Pkcs11Attribute> template) {
        PackedTemplate packed = PackedTemplate.from(template);
        return Pkcs11NativeBridge.cCreateObject(
                requireHandle(), sessionHandle,
                packed.types(), packed.kinds(), packed.longs(), packed.bytes());
    }

    @Override
    public void cSignInit(long sessionHandle, Pkcs11Mechanism mechanism, long keyHandle) {
        Pkcs11NativeBridge.cSignInit(
                requireHandle(),
                sessionHandle,
                mechanism.mechanismType(),
                mechanism.pss(),
                mechanism.pssHashAlg(),
                mechanism.pssMgf(),
                mechanism.pssSaltLen(),
                keyHandle);
    }

    @Override
    public byte[] cSign(long sessionHandle, byte[] data) {
        return Pkcs11NativeBridge.cSign(requireHandle(), sessionHandle, data);
    }

    @Override
    public void close() {
        long handle = moduleHandle.getAndSet(0L);
        if (handle != 0L) {
            Pkcs11NativeBridge.unloadModule(handle);
        }
    }

    private long requireHandle() {
        long h = moduleHandle.get();
        if (h == 0L) {
            throw new IllegalStateException("PKCS#11 module already closed: " + libraryPath);
        }
        return h;
    }

    private static byte[] toUtf8Bytes(char[] chars) {
        if (chars == null || chars.length == 0) {
            return new byte[0];
        }
        ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        byte[] result = new byte[bb.remaining()];
        bb.get(result);
        if (bb.hasArray()) {
            Arrays.fill(bb.array(), (byte) 0);
        }
        return result;
    }

    private record PackedTemplate(long[] types, int[] kinds, long[] longs, byte[][] bytes) {
        static PackedTemplate from(List<Pkcs11Attribute> list) {
            if (list == null || list.isEmpty()) {
                return new PackedTemplate(new long[0], new int[0], new long[0], new byte[0][]);
            }
            int n = list.size();
            long[] types = new long[n];
            int[] kinds = new int[n];
            long[] longs = new long[n];
            byte[][] bytes = new byte[n][];
            for (int i = 0; i < n; i++) {
                Pkcs11Attribute a = list.get(i);
                types[i] = a.type();
                kinds[i] = a.kind();
                longs[i] = a.longValue();
                bytes[i] = a.byteValue();
            }
            return new PackedTemplate(types, kinds, longs, bytes);
        }
    }
}

