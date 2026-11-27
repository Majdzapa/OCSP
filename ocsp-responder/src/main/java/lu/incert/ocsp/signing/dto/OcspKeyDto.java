package lu.incert.ocsp.signing.dto;

import java.time.Instant;

/**
 * Projection of a persisted cryptographic asymmetric key ({@code ocsp_keys}) extracted once
 * from the PKCS#11 HSM token.
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
        Instant createdAt
) {}

