package com.company.incert.ocsp.signing.pkcs11;

import java.nio.charset.StandardCharsets;

/**
 * Typed PKCS#11 {@code CK_ATTRIBUTE} descriptor.
 */
public record Pkcs11Attribute(long type, int kind, long longValue, byte[] byteValue) {

    public static final int KIND_BYTES = 0;
    public static final int KIND_ULONG = 1;
    public static final int KIND_BOOL  = 2;

    public static Pkcs11Attribute ofBytes(long type, byte[] value) {
        return new Pkcs11Attribute(type, KIND_BYTES, 0L, value);
    }

    public static Pkcs11Attribute ofString(long type, String value) {
        return new Pkcs11Attribute(type, KIND_BYTES, 0L,
                value != null ? value.getBytes(StandardCharsets.UTF_8) : new byte[0]);
    }

    public static Pkcs11Attribute ofUlong(long type, long value) {
        return new Pkcs11Attribute(type, KIND_ULONG, value, null);
    }

    public static Pkcs11Attribute ofBool(long type, boolean value) {
        return new Pkcs11Attribute(type, KIND_BOOL, value ? 1L : 0L, null);
    }
}

