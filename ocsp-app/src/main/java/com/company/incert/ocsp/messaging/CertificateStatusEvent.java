package com.company.incert.ocsp.messaging;

import com.company.incert.ocsp.entity.CertificateStatus;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * JSON payload of a {@code CertificateStatusChanged} event published by the KMS simulator.
 * Also used by the reconciliation job, which maps KMS snapshot rows to the same shape.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CertificateStatusEvent(
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

