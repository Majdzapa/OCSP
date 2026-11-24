package lu.incert.ocsp.signing.port;

/**
 * Immutable configuration descriptor used by {@code CryptoDeviceAdapterFactory} implementations
 * to construct runtime {@link CryptoProviderPort} instances without coupling to JPA entities.
 */
public record CryptoDeviceSpec(
        String deviceId,
        String providerCode,
        String wrapperType,
        String libraryPath,
        String libraryWrapperPath,
        String tokenLabel,
        Long slotId,
        int slotListIndex,
        int poolSize,
        boolean prehashInJvm
) {}

