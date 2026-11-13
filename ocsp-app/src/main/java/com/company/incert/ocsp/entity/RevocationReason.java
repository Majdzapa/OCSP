package com.company.incert.ocsp.entity;

/** RFC 5280 CRLReason codes. */
public enum RevocationReason {
    UNSPECIFIED(0),
    KEY_COMPROMISE(1),
    CA_COMPROMISE(2),
    AFFILIATION_CHANGED(3),
    SUPERSEDED(4),
    CESSATION_OF_OPERATION(5),
    CERTIFICATE_HOLD(6),
    REMOVE_FROM_CRL(8),
    PRIVILEGE_WITHDRAWN(9),
    AA_COMPROMISE(10);

    private final int code;

    RevocationReason(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    /** Lenient parse: returns null for null/blank/unknown values. */
    public static RevocationReason parse(String value) {
        if (value == null || value.isBlank() || "null".equals(value)) {
            return null;
        }
        try {
            return RevocationReason.valueOf(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

