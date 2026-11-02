package com.company.ocsp.sync.service;

import com.company.ocsp.sync.dto.CertificateEventDto;
import com.company.ocsp.sync.model.CertEventAudit;
import com.company.ocsp.sync.model.RevocationStatus;
import com.company.ocsp.sync.repository.CertEventAuditRepository;
import com.company.ocsp.sync.repository.RevocationStatusRepository;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Map;

/**
 * Core business service for processing KMS certificate domain events.
 *
 * <p>Responsibilities:
 * <ol>
 *   <li>De-duplicate via {@code source_event_id} unique constraint (idempotent upsert).
 *   <li>Persist revocation status in MariaDB within a transaction.
 *   <li>Record an audit row for every event (PROCESSED or FAILED).
 *   <li>Emit a cache-invalidation message so responder nodes proactively evict
 *       stale cached responses within the &lt;60 second SLA.
 * </ol>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateEventProcessor {

    private final RevocationStatusRepository revocationStatusRepository;
    private final CertEventAuditRepository   certEventAuditRepository;
    private final RabbitTemplate             rabbitTemplate;
    private final MeterRegistry              meterRegistry;

    @Value("${ocsp.rabbitmq.cache-invalidation-exchange:ocsp.internal}")
    private String cacheInvalidationExchange;

    @Value("${ocsp.rabbitmq.cache-invalidation-routing-key:ocsp.cache.invalidate}")
    private String cacheInvalidationRoutingKey;

    /**
     * Processes a single certificate domain event.
     *
     * @param event the parsed event DTO
     * @throws IllegalArgumentException if the event payload is invalid
     */
    @Transactional
    public void process(CertificateEventDto event) {
        log.info("Processing event: id={} type={} serial={}",
            event.getEventId(), event.getEventType(), event.getSerialNumberHex());

        byte[] issuerNameHash = Hex.decode(event.getIssuerNameHashHex());
        byte[] issuerKeyHash  = Hex.decode(event.getIssuerKeyHashHex());
        byte[] serialNumber   = Hex.decode(event.getSerialNumberHex());
        Instant now           = Instant.now();

        RevocationStatus.CertStatus newStatus = mapStatus(event.getEventType());

        // Idempotent upsert: try update first, then insert if not found
        int updated = revocationStatusRepository.updateByCertId(
            issuerNameHash, issuerKeyHash, serialNumber,
            newStatus,
            event.getRevocationTime(),
            event.getRevocationReason(),
            now,
            event.getEventId(),
            now
        );

        if (updated == 0) {
            // First time we see this certificate — insert
            RevocationStatus record = RevocationStatus.builder()
                .issuerNameHash(issuerNameHash)
                .issuerKeyHash(issuerKeyHash)
                .serialNumber(serialNumber)
                .status(newStatus)
                .revocationTime(event.getRevocationTime())
                .revocationReason(event.getRevocationReason())
                .thisUpdate(now)
                .sourceEventId(event.getEventId())
                .updatedAt(now)
                .build();
            revocationStatusRepository.save(record);
        }

        // Audit
        markAuditProcessed(event.getEventId(), now);

        // Emit cache-invalidation signal
        publishInvalidation(event, issuerNameHash, issuerKeyHash, serialNumber);

        meterRegistry.counter("ocsp.sync.events.processed",
            "type", event.getEventType()).increment();
        log.info("Processed event: id={} → status={}", event.getEventId(), newStatus);
    }

    /**
     * Records a failed event in the audit log.  Called by the consumer on exception,
     * before nacking to the DLQ.
     */
    @Transactional
    public void markAuditFailed(String eventId, String errorMessage) {
        certEventAuditRepository.findById(eventId).ifPresent(audit -> {
            audit.setStatus(CertEventAudit.ProcessingStatus.FAILED);
            audit.setErrorMessage(errorMessage);
            certEventAuditRepository.save(audit);
        });
    }

    // -------------------------------------------------------------------------

    private RevocationStatus.CertStatus mapStatus(String eventType) {
        return switch (eventType) {
            case "CertificateIssued"    -> RevocationStatus.CertStatus.GOOD;
            case "CertificateRevoked",
                 "CertificateHeld"      -> RevocationStatus.CertStatus.REVOKED;
            case "CertificateUnrevoked" -> RevocationStatus.CertStatus.GOOD;
            default -> throw new IllegalArgumentException(
                "Unknown event type: " + eventType);
        };
    }

    private void markAuditProcessed(String eventId, Instant processedAt) {
        certEventAuditRepository.findById(eventId).ifPresent(audit -> {
            audit.setStatus(CertEventAudit.ProcessingStatus.PROCESSED);
            audit.setProcessedAt(processedAt);
            certEventAuditRepository.save(audit);
        });
    }

    private void publishInvalidation(
            CertificateEventDto event,
            byte[] issuerNameHash,
            byte[] issuerKeyHash,
            byte[] serialNumber) {
        try {
            Map<String, String> msg = Map.of(
                "issuerNameHashHex", Hex.toHexString(issuerNameHash),
                "issuerKeyHashHex",  Hex.toHexString(issuerKeyHash),
                "serialNumberHex",   Hex.toHexString(serialNumber),
                "eventId",           event.getEventId()
            );
            rabbitTemplate.convertAndSend(
                cacheInvalidationExchange, cacheInvalidationRoutingKey, msg);
            log.debug("Published cache-invalidation for serial={}", event.getSerialNumberHex());
        } catch (Exception e) {
            // Cache invalidation failure is non-fatal: the cached entry will expire
            // naturally.  Log and meter so ops can investigate if it recurs.
            log.warn("Failed to publish cache-invalidation signal for eventId={}: {}",
                event.getEventId(), e.getMessage());
            meterRegistry.counter("ocsp.sync.cache.invalidation.failure").increment();
        }
    }
}
