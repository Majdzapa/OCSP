package com.company.incert.ocsp.status.dto;

import com.company.incert.ocsp.status.entity.CertificateStatus;

import java.time.Instant;

/**
 * Domain command representing an incoming certificate status transition,
 * decoupling {@code status} from transport-specific messaging DTOs.
 */
public record CertificateStatusUpdateCommand(
    String eventId,
    Instant occurredAt,
    String issuerKeyHashHex,
    String issuerNameHashHex,
    String serialNumberHex,
    CertificateStatus status,
    Instant revocationTime,
    String revocationReason,
    long sequence
) {}

