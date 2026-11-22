package com.company.incert.ocsp.signing.dto;

import java.time.Instant;
import java.util.List;

/**
 * Report produced by the daily signing certificate validity check job and on-demand validity inspections.
 * Raises alerts for any signing certificate expiring within {@code alertThresholdDays} (default 3 days) or already expired.
 */
public record SigningCertValidityReportDto(
        Instant lastCheckedAt,
        int alertThresholdDays,
        String dailyCron,
        int totalCount,
        int activeCount,
        int healthyCount,
        int expiringWithinThresholdCount,
        int expiredCount,
        boolean alertActive,
        List<ValidityAlertDto> alerts,
        List<CertificateValidityItemDto> certificates
) {
    public record ValidityAlertDto(
            Long certificateId,
            String alias,
            String keyLabel,
            String subjectDn,
            String issuerDn,
            Instant notAfter,
            long daysUntilExpiry,
            long hoursUntilExpiry,
            boolean active,
            String severity, // "EXPIRED" or "EXPIRING_SOON"
            String message
    ) {}

    public record CertificateValidityItemDto(
            Long id,
            String alias,
            String keyLabel,
            String subjectDn,
            String issuerDn,
            String serialNumber,
            String signatureAlgorithm,
            Instant notBefore,
            Instant notAfter,
            long daysUntilExpiry,
            long hoursUntilExpiry,
            boolean active,
            boolean expired,
            boolean expiringWithinThreshold,
            String validityStatus // "HEALTHY", "EXPIRING_SOON", "EXPIRED"
    ) {}
}

