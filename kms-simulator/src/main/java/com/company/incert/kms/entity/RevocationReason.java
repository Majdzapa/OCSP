package com.company.incert.kms.entity;

import lombok.Getter;

/**
 * RFC 5280 CRLReason enumeration.
 */
@Getter
public enum RevocationReason {
    UNSPECIFIED(0),
    KEY_COMPROMISE(1),
    CA_COMPROMISE(2),
    AFFILIATION_CHANGED(3),
    SUPERSEDED(4),
    CESSATION_OF_OPERATION(5),
    CERTIFICATE_HOLD(6),
    PRIVILEGE_WITHDRAWN(9),
    AA_COMPROMISE(10);

    private final int code;

    RevocationReason(int code) {
        this.code = code;
    }
}
