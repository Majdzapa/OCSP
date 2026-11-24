package lu.incert.ocsp.signing.provider;

import lu.incert.ocsp.signing.port.CryptoDeviceSpec;
import lu.incert.ocsp.signing.port.CryptoProviderPort;
import lu.incert.ocsp.signing.port.DiscoveredSlotInfo;

import java.util.List;

/**
 * Open-Closed factory port mapping a {@code wrapperType} (e.g. {@code PKCS11J} or custom
 * {@code CryptoDeviceAdapterFactory} Spring beans such as KMS/KMIP)
 * to a runtime {@link CryptoProviderPort} instance initialized in {@code LOCKED} state.
 */
public interface CryptoDeviceAdapterFactory {

    boolean supports(String wrapperType);

    CryptoProviderPort create(CryptoDeviceSpec spec);

    default List<DiscoveredSlotInfo> discoverSlots(String libraryPath, String libraryWrapperPath) {
        return List.of();
    }
}

