package lu.incert.ocsp.signing.pkcs11;

import java.util.Arrays;

/**
 * Configuration for a single PKCS#11 signing device/slot managed by {@link Pkcs11Engine}.
 */
public record Pkcs11ProviderConfig(
        String providerId,
        String libraryPath,
        String libraryWrapperPath,
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
        libraryWrapperPath = (libraryWrapperPath == null || libraryWrapperPath.isBlank())
                ? null
                : libraryWrapperPath.trim();
        if (poolSize <= 0) {
            poolSize = 4;
        }
        pin = pin != null ? pin.clone() : new char[0];
    }

    public Pkcs11ProviderConfig(
            String providerId,
            String libraryPath,
            String tokenLabel,
            Long slotId,
            int slotListIndex,
            char[] pin,
            int poolSize,
            boolean prehashInJvm) {
        this(providerId, libraryPath, null, tokenLabel, slotId, slotListIndex, pin, poolSize, prehashInJvm);
    }

    public char[] pinCopy() {
        return pin.clone();
    }

    public void wipePin() {
        Arrays.fill(pin, '\0');
    }
}

