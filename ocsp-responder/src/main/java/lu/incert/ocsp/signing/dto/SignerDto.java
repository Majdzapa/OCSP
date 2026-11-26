package lu.incert.ocsp.signing.dto;

import java.time.Instant;
import java.util.List;

/**
 * Full projection of an OCSP Signer aggregate root, including its ordered HSM Vslots,
 * cryptographic key & algorithm policy, generated CSR, and imported X.509 certificate.
 */
public record SignerDto(
        Long id,
        String code,
        String name,
        String status,
        String subjectDn,
        String keyLabel,
        String keyAlgorithm,
        int keySize,
        String signatureAlgorithm,
        List<SignerVslotDto> vslots,
        boolean hasCsr,
        String csrPem,
        Instant csrGeneratedAt,
        boolean hasCertificate,
        SignerCertificateDto certificate,
        boolean active,
        Instant activatedAt,
        Instant createdAt,
        Instant updatedAt
) {
    public record SignerVslotDto(
            Long deviceDbId,
            String deviceId,
            Long providerId,
            String providerCode,
            String providerName,
            String wrapperType,
            String libraryPath,
            String libraryWrapperPath,
            String tokenLabel,
            Long slotId,
            int slotListIndex,
            int priorityOrder,
            String role,
            String activationState,
            boolean healthy,
            boolean keyPresent
    ) {}

    public record SignerCertificateDto(
            Long signingCertificateId,
            String subjectDn,
            String issuerDn,
            String serialNumber,
            Instant notBefore,
            Instant notAfter,
            long daysUntilExpiry,
            boolean expired,
            String signatureAlgorithm,
            String certificatePem
    ) {}
}

