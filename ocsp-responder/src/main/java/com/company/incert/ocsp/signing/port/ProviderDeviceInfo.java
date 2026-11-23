package com.company.incert.ocsp.signing.port;

import java.util.List;
import java.util.Map;

/**
 * Snapshot metadata describing one configured cryptographic signing device managed by {@code PkcsProviders}.
 */
public record ProviderDeviceInfo(
        String providerId,
        String providerType,
        String libraryPath,
        String libraryWrapperPath,
        String tokenLabel,
        long slotId,
        String activationState,
        boolean healthy,
        String statusMessage,
        List<String> keyLabels,
        Map<String, String> keyAlgorithms
) {
    public ProviderDeviceInfo(
            String providerId,
            String providerType,
            String libraryPath,
            String tokenLabel,
            long slotId,
            boolean healthy,
            String statusMessage,
            List<String> keyLabels,
            Map<String, String> keyAlgorithms) {
        this(
                providerId,
                providerType,
                libraryPath,
                "embedded",
                tokenLabel,
                slotId,
                healthy ? DeviceActivationState.ACTIVE.name() : DeviceActivationState.LOCKED.name(),
                healthy,
                statusMessage,
                keyLabels,
                keyAlgorithms
        );
    }
}
