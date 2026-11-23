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
        String tokenLabel,
        long slotId,
        boolean healthy,
        String statusMessage,
        List<String> keyLabels,
        Map<String, String> keyAlgorithms
) {}

