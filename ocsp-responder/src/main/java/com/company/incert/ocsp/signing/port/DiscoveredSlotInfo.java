package com.company.incert.ocsp.signing.port;

/**
 * Hardware/token slot metadata discovered live from a PKCS#11 provider without authentication (zero PIN).
 */
public record DiscoveredSlotInfo(
        long slotId,
        int slotListIndex,
        String tokenLabel,
        String manufacturerId,
        String model,
        String serialNumber,
        boolean initialized,
        long flags
) {}

