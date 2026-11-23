package com.company.incert.pkcs11j;

/**
 * Token metadata obtained from PKCS#11 C_GetTokenInfo.
 */
public record TokenInfo(
        long slotId,
        String label,
        String manufacturerId,
        String model,
        String serialNumber,
        long flags
) {}

