package lu.incert.ocsp.signing.dto;

import java.time.Instant;

/**
 * Projection of a persisted cryptographic asymmetric key ({@code ocsp_keys}) extracted once
 * from the PKCS#11 HSM token, enriched with EJBCA-style live token &amp; key availability status
 * (computed from in-memory token state + MariaDB with zero PKCS#11 calls).
 */
public record OcspKeyDto(
        Long id,
        String keyLabel,
        String ckaIdHex,
        Long tokenDeviceId,
        String tokenDeviceCode,
        String tokenLabel,
        String keyAlgorithm,
        int keySize,
        String publicKeyPem,
        String publicKeySha1,
        Instant generatedAt,
        Instant createdAt,
        String tokenState,
        boolean tokenActive,
        String status,
        Long boundSignerId,
        String boundSignerCode,
        String boundSignerName,
        boolean hasCertificate,
        Long certDaysUntilExpiry
) {
    /** Backwards-compatible constructor when live signer/token context is not populated. */
    public OcspKeyDto(
            Long id,
            String keyLabel,
            String ckaIdHex,
            Long tokenDeviceId,
            String tokenDeviceCode,
            String tokenLabel,
            String keyAlgorithm,
            int keySize,
            String publicKeyPem,
            String publicKeySha1,
            Instant generatedAt,
            Instant createdAt) {
        this(id, keyLabel, ckaIdHex, tokenDeviceId, tokenDeviceCode, tokenLabel,
                keyAlgorithm, keySize, publicKeyPem, publicKeySha1, generatedAt, createdAt,
                "LOCKED", false, "UNAVAILABLE", null, null, null, false, null);
    }
}
