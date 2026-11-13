package com.company.incert.kms.entity;

import java.time.Instant;
import java.util.UUID;

/**
 * Event payload emitted when a certificate's status changes.
 */
public record CertificateStatusEvent(
        String eventId,
        String eventType,
        Instant occurredAt,
        String issuerKeyHashHex,
        String issuerNameHashHex,
        String serialNumberHex,
        CertificateStatus status,
        Instant revocationTime,
        RevocationReason revocationReason,
        long sequence,
        int schemaVersion
) {
    public static CertificateStatusEvent from(Certificate cert) {
        return new CertificateStatusEvent(
                UUID.randomUUID().toString(),
                "CertificateStatusChanged",
                Instant.now(),
                cert.getIssuerKeyHashHex(),
                cert.getIssuerNameHashHex(),
                cert.getSerialNumberHex(),
                cert.getStatus(),
                cert.getRevocationTime(),
                cert.getRevocationReason(),
                cert.getSequence(),
                1
        );
    }
}
