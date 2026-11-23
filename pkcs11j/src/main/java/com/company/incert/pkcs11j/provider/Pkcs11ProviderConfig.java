package com.company.incert.pkcs11j.provider;

/**
 * Configuration for a single PKCS#11 signing device/slot managed by {@link PkcsProviders}.
 */
public record Pkcs11ProviderConfig(
        String providerId,
        String libraryPath,
        String tokenLabel,
        Long slotId,
        int slotListIndex,
        char[] pin,
        int poolSize,
        boolean prehashInJvm
) {
    public Pkcs11ProviderConfig {
        if (providerId == null || providerId.isBlank()) {
            throw new IllegalArgumentException("providerId must not be blank");
        }
        if (libraryPath == null || libraryPath.isBlank()) {
            throw new IllegalArgumentException("libraryPath must not be blank for provider '" + providerId + "'");
        }
        if (poolSize <= 0) {
            poolSize = 4;
        }
        pin = pin != null ? pin.clone() : new char[0];
    }

    public char[] pinCopy() {
        return pin.clone();
    }
}

