package lu.incert.ocsp.signing.pkcs11;

/**
 * Token metadata obtained from PKCS#11 {@code C_GetTokenInfo}.
 */
public record TokenInfo(
        long slotId,
        String label,
        String manufacturerId,
        String model,
        String serialNumber,
        long flags
) {}

