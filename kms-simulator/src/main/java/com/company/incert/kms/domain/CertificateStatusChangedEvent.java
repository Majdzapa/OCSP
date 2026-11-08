package com.company.incert.kms.domain;

import java.time.Instant;
import java.util.UUID;

/**
 * Domain event emitted whenever a certificate's status changes.
 * Schema version is always 1 for this iteration.
 */
public record CertificateStatusChangedEvent(
        String eventId,
        String eventType,          // CertificateStatusChanged
        Instant occurredAt,
        String issuerKeyHashHex,
        String issuerNameHashHex,
        String serialNumberHex,
        CertificateStatus status,
        Instant revocationTime,
        RevocationReason revocationReason,
        long sequence,
        int schemaVersion          // always 1
) {
    public static CertificateStatusChangedEvent from(Certificate cert) {
        return new CertificateStatusChangedEvent(
                UUID.randomUUID().toString(),
                "CertificateStatusChanged",
                Instant.now(),
                cert.issuerKeyHashHex(),
                cert.issuerNameHashHex(),
                cert.serialNumberHex(),
                cert.status(),
                cert.revocationTime(),
                cert.revocationReason(),
                cert.sequence(),
                1
        );
    }
}
