package com.company.incert.ocsp.signing.port;

/**
 * Thrown when an operation targets a cryptographic device that is registered in {@code PkcsProviders}
 * but currently {@link DeviceActivationState#LOCKED} (awaiting runtime PIN unlock).
 */
public class DeviceLockedException extends IllegalStateException {

    public DeviceLockedException(String message) {
        super(message);
    }
}

