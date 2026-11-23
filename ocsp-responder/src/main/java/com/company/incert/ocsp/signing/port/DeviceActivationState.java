package com.company.incert.ocsp.signing.port;

/**
 * Runtime activation lifecycle state for a cryptographic signing device (Pattern 2).
 */
public enum DeviceActivationState {
    /** Device metadata is registered from DB, but no PIN has been supplied yet (no C_Login). */
    LOCKED,
    /** Device has been unlocked at runtime with an admin PIN and has open PKCS#11 sessions. */
    ACTIVE,
    /** Device failed initialization or health verification. */
    ERROR
}

