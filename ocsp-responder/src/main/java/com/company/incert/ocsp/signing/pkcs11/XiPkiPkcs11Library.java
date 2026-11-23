package com.company.incert.ocsp.signing.pkcs11;

import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.CK_RSA_PKCS_PSS_PARAMS;
import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import iaik.pkcs.pkcs11.wrapper.PKCS11Implementation;
import org.xipki.pkcs11.wrapper.PKCS11Module;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@link Pkcs11LibraryPort} backed directly by Maven Central's {@code org.xipki:ipkcs11wrapper} JAR
 * (zero custom C compilation or build scripts).
 * <p>
 * Connected {@link PKCS11} module handles are retained in a static cache so JVM garbage collection
 * never calls {@link PKCS11Implementation#finalize()} -&gt; {@code dlclose()} on active worker threads
 * ({@code C_Finalize} resets PKCS#11 state cleanly on device lock/unregister).
 */
public final class XiPkiPkcs11Library implements Pkcs11LibraryPort {

    public static final String EMBEDDED = "embedded";

    private static final Map<String, PKCS11> MODULE_CACHE = new ConcurrentHashMap<>();
    private static volatile String loadedWrapperSource;

    private final String libraryPath;
    private final PKCS11 pkcs11;

    public XiPkiPkcs11Library(String libraryPath) {
        this(libraryPath, EMBEDDED);
    }

    public XiPkiPkcs11Library(String libraryPath, String libraryWrapperPath) {
        if (libraryPath == null || libraryPath.isBlank()) {
            throw new IllegalArgumentException("PKCS#11 library path must not be blank");
        }
        String canonicalLib = Path.of(libraryPath.trim()).toAbsolutePath().normalize().toString();
        String explicitWrapper = normalizeWrapperPath(libraryWrapperPath);
        this.libraryPath = canonicalLib;
        this.pkcs11 = acquireNativeModule(canonicalLib, explicitWrapper);
    }

    private static synchronized PKCS11 acquireNativeModule(String canonicalLib, String explicitWrapper) {
        if (explicitWrapper != null && loadedWrapperSource != null && !explicitWrapper.equals(loadedWrapperSource)) {
            throw new IllegalStateException("PKCS#11 JNI wrapper already loaded from '" + loadedWrapperSource
                    + "' and cannot be reloaded with '" + explicitWrapper + "' in the same JVM");
        }
        return MODULE_CACHE.computeIfAbsent(canonicalLib, path -> openNativeModule(path, explicitWrapper));
    }

    private static PKCS11 openNativeModule(String canonicalLib, String explicitWrapper) {
        try {
            if (loadedWrapperSource == null) {
                if (explicitWrapper != null) {
                    System.load(explicitWrapper);
                    PKCS11Implementation.initializeLibrary();
                    loadedWrapperSource = explicitWrapper;
                    return new PKCS11Implementation(canonicalLib);
                }
                PKCS11Module module = PKCS11Module.getInstance(canonicalLib);
                loadedWrapperSource = EMBEDDED;
                return module.getPKCS11Module();
            }
            if (EMBEDDED.equals(loadedWrapperSource)) {
                return PKCS11Module.getInstance(canonicalLib).getPKCS11Module();
            }
            return new PKCS11Implementation(canonicalLib);
        } catch (IOException e) {
            throw new IllegalStateException("Failed loading PKCS#11 module '" + canonicalLib + "': " + e.getMessage(), e);
        }
    }

    private static String normalizeWrapperPath(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String trimmed = raw.trim();
        if (EMBEDDED.equalsIgnoreCase(trimmed) || "auto".equalsIgnoreCase(trimmed)) {
            return null;
        }
        return Path.of(trimmed).toAbsolutePath().normalize().toString();
    }

    @Override
    public String getLibraryPath() {
        return libraryPath;
    }

    @Override
    public long cInitialize(long flags) {
        try {
            Object initArgs = null;
            if (flags != 0L) {
                CK_C_INITIALIZE_ARGS args = new CK_C_INITIALIZE_ARGS();
                args.flags = flags;
                initArgs = args;
            }
            pkcs11.C_Initialize(initArgs, true);
            return Pkcs11Constants.CKR_OK;
        } catch (PKCS11Exception e) {
            return e.getErrorCode();
        }
    }

    @Override
    public long cFinalize() {
        try {
            pkcs11.C_Finalize(null);
            return Pkcs11Constants.CKR_OK;
        } catch (PKCS11Exception e) {
            return e.getErrorCode();
        }
    }

    @Override
    public long[] cGetSlotList(boolean tokenPresent) {
        try {
            long[] slots = pkcs11.C_GetSlotList(tokenPresent);
            return slots != null ? slots : new long[0];
        } catch (PKCS11Exception e) {
            throw translate("C_GetSlotList", e);
        }
    }

    @Override
    public TokenInfo cGetTokenInfo(long slotId) {
        try {
            CK_TOKEN_INFO info = pkcs11.C_GetTokenInfo(slotId);
            return new TokenInfo(
                    slotId,
                    charsToTrimmedString(info.label),
                    charsToTrimmedString(info.manufacturerID),
                    charsToTrimmedString(info.model),
                    charsToTrimmedString(info.serialNumber),
                    info.flags
            );
        } catch (PKCS11Exception e) {
            throw translate("C_GetTokenInfo", e);
        }
    }

    @Override
    public long cOpenSession(long slotId, long flags) {
        try {
            return pkcs11.C_OpenSession(slotId, flags, null, null);
        } catch (PKCS11Exception e) {
            throw translate("C_OpenSession", e);
        }
    }

    @Override
    public void cCloseSession(long sessionHandle) {
        try {
            pkcs11.C_CloseSession(sessionHandle);
        } catch (PKCS11Exception e) {
            if (e.getErrorCode() != Pkcs11Constants.CKR_SESSION_HANDLE_INVALID) {
                throw translate("C_CloseSession", e);
            }
        }
    }

    @Override
    public void cCloseAllSessions(long slotId) {
        try {
            pkcs11.C_CloseAllSessions(slotId);
        } catch (PKCS11Exception e) {
            throw translate("C_CloseAllSessions", e);
        }
    }

    @Override
    public long cLogin(long sessionHandle, long userType, char[] pin) {
        char[] copy = pin != null ? pin.clone() : new char[0];
        try {
            pkcs11.C_Login(sessionHandle, userType, copy, true);
            return Pkcs11Constants.CKR_OK;
        } catch (PKCS11Exception e) {
            return e.getErrorCode();
        } finally {
            Arrays.fill(copy, '\0');
        }
    }

    @Override
    public long cLogout(long sessionHandle) {
        try {
            pkcs11.C_Logout(sessionHandle);
            return Pkcs11Constants.CKR_OK;
        } catch (PKCS11Exception e) {
            return e.getErrorCode();
        }
    }

    @Override
    public void cFindObjectsInit(long sessionHandle, List<Pkcs11Attribute> template) {
        try {
            pkcs11.C_FindObjectsInit(sessionHandle, toCkAttributes(template), true);
        } catch (PKCS11Exception e) {
            throw translate("C_FindObjectsInit", e);
        }
    }

    @Override
    public long[] cFindObjects(long sessionHandle, int maxCount) {
        if (maxCount <= 0) {
            return new long[0];
        }
        try {
            long[] found = pkcs11.C_FindObjects(sessionHandle, maxCount);
            return found != null ? found : new long[0];
        } catch (PKCS11Exception e) {
            throw translate("C_FindObjects", e);
        }
    }

    @Override
    public void cFindObjectsFinal(long sessionHandle) {
        try {
            pkcs11.C_FindObjectsFinal(sessionHandle);
        } catch (PKCS11Exception e) {
            throw translate("C_FindObjectsFinal", e);
        }
    }

    @Override
    public byte[] cGetAttributeValue(long sessionHandle, long objectHandle, long attrType) {
        Object val = readRawAttribute(sessionHandle, objectHandle, attrType, "C_GetAttributeValue");
        if (val == null) {
            return null;
        }
        if (val instanceof byte[] bytes) {
            return bytes;
        }
        if (val instanceof char[] chars) {
            return new String(chars).getBytes(StandardCharsets.UTF_8);
        }
        if (val instanceof String s) {
            return s.getBytes(StandardCharsets.UTF_8);
        }
        throw new IllegalStateException(
                "Unexpected PKCS#11 attribute value type " + val.getClass().getName() + " for attr=" + attrType);
    }

    @Override
    public long cGetAttributeUlong(long sessionHandle, long objectHandle, long attrType) {
        Object val = readRawAttribute(sessionHandle, objectHandle, attrType, "C_GetAttributeValue(ulong)");
        if (val instanceof Number n) {
            return n.longValue();
        }
        throw new IllegalStateException("Expected numeric value for PKCS#11 ulong attribute " + attrType
                + ", got " + (val != null ? val.getClass().getName() : "null"));
    }

    private Object readRawAttribute(long sessionHandle, long objectHandle, long attrType, String fnLabel) {
        CK_ATTRIBUTE attr = new CK_ATTRIBUTE();
        attr.type = attrType;
        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[]{attr};
        try {
            pkcs11.C_GetAttributeValue(sessionHandle, objectHandle, template, true);
        } catch (PKCS11Exception e) {
            throw translate(fnLabel, e);
        }
        // ipkcs11wrapper replaces template[0] with a freshly allocated CK_ATTRIBUTE in native JNI
        return template[0] != null ? template[0].pValue : null;
    }

    @Override
    public long[] cGenerateKeyPair(
            long sessionHandle,
            Pkcs11Mechanism mechanism,
            List<Pkcs11Attribute> publicKeyTemplate,
            List<Pkcs11Attribute> privateKeyTemplate) {
        try {
            return pkcs11.C_GenerateKeyPair(
                    sessionHandle,
                    toCkMechanism(mechanism),
                    toCkAttributes(publicKeyTemplate),
                    toCkAttributes(privateKeyTemplate),
                    true);
        } catch (PKCS11Exception e) {
            throw translate("C_GenerateKeyPair", e);
        }
    }

    @Override
    public long cCreateObject(long sessionHandle, List<Pkcs11Attribute> template) {
        try {
            return pkcs11.C_CreateObject(sessionHandle, toCkAttributes(template), true);
        } catch (PKCS11Exception e) {
            throw translate("C_CreateObject", e);
        }
    }

    @Override
    public void cSignInit(long sessionHandle, Pkcs11Mechanism mechanism, long keyHandle) {
        try {
            pkcs11.C_SignInit(sessionHandle, toCkMechanism(mechanism), keyHandle, true);
        } catch (PKCS11Exception e) {
            throw translate("C_SignInit", e);
        }
    }

    @Override
    public byte[] cSign(long sessionHandle, byte[] data) {
        try {
            return pkcs11.C_Sign(sessionHandle, data);
        } catch (PKCS11Exception e) {
            throw translate("C_Sign", e);
        }
    }

    @Override
    public void close() {
        // Cached module handle stays mapped for JVM lifetime; C_Finalize manages token cleanup cleanly.
    }

    private static CK_ATTRIBUTE[] toCkAttributes(List<Pkcs11Attribute> template) {
        if (template == null || template.isEmpty()) {
            return new CK_ATTRIBUTE[0];
        }
        CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[template.size()];
        for (int i = 0; i < template.size(); i++) {
            Pkcs11Attribute src = template.get(i);
            CK_ATTRIBUTE ck = new CK_ATTRIBUTE();
            ck.type = src.type();
            ck.pValue = switch (src.kind()) {
                case Pkcs11Attribute.KIND_BOOL -> Boolean.valueOf(src.longValue() != 0L);
                case Pkcs11Attribute.KIND_ULONG -> Long.valueOf(src.longValue());
                default -> (src.type() == Pkcs11Constants.CKA_LABEL && src.byteValue() != null)
                        ? new String(src.byteValue(), StandardCharsets.UTF_8).toCharArray()
                        : src.byteValue();
            };
            attrs[i] = ck;
        }
        return attrs;
    }

    private static CK_MECHANISM toCkMechanism(Pkcs11Mechanism mechanism) {
        CK_MECHANISM ck = new CK_MECHANISM();
        ck.mechanism = mechanism.mechanismType();
        if (mechanism.pss()) {
            CK_RSA_PKCS_PSS_PARAMS pss = new CK_RSA_PKCS_PSS_PARAMS();
            pss.hashAlg = mechanism.pssHashAlg();
            pss.mgf = mechanism.pssMgf();
            pss.sLen = mechanism.pssSaltLen();
            ck.pParameter = pss;
        }
        return ck;
    }

    private static Pkcs11Exception translate(String fnName, PKCS11Exception e) {
        return new Pkcs11Exception(fnName, e.getErrorCode());
    }

    private static String charsToTrimmedString(char[] chars) {
        return chars == null ? "" : new String(chars).trim();
    }
}
