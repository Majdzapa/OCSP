package com.company.incert.ocsp.messaging;

import java.time.Instant;
import java.util.List;

/**
 * Purely event-driven Outbox Manifest received over RabbitMQ from KMS Simulator.
 * Enables Outbox <-> Inbox reconciliation with zero REST calls.
 */
public record OutboxManifestEvent(
        String manifestId,
        Instant generatedAt,
        int totalCertificates,
        long totalOutboxEvents,
        long sentOutboxEvents,
        long pendingOutboxEvents,
        List<String> outboxEventIds,
        List<CertificateDigest> certificates
) {
    public record CertificateDigest(
            String serialNumberHex,
            String status,
            String revocationReason,
            long sequence,
            String latestEventId
    ) {}
}

