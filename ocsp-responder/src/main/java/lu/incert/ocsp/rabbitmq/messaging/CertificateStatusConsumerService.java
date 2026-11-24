package lu.incert.ocsp.rabbitmq.messaging;


import lu.incert.ocsp.rabbitmq.entity.InboxEvent;
import lu.incert.ocsp.rabbitmq.repository.InboxEventRepository;
import lu.incert.ocsp.status.dto.CertificateStatusUpdateCommand;
import lu.incert.ocsp.status.service.CertificateStatusService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * Default implementation of {@link CertificateStatusConsumer}.
 *
 * The entire consume() method runs in a single transaction so the inbox
 * record and the revocation_status row are always consistent: either both
 * commit or neither does. Failures are recorded separately via {@link InboxFailureRecorder}
 * with the RabbitMQ deliveryTag so they can be traced even after rollback/DLQ routing.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateStatusConsumerService implements CertificateStatusConsumer {

    private final CertificateStatusService statusService;
    private final InboxEventRepository inboxRepository;
    private final ObjectMapper objectMapper;
    private final InboxFailureRecorder failureRecorder;

    @Override
    @Transactional
    public void consume(String payload, String messageId, Long deliveryTag, String consumerQueue, Boolean redelivered) {
        Instant now = Instant.now();
        CertificateStatusEvent event;
        try {
            event = objectMapper.readValue(payload, CertificateStatusEvent.class);
        } catch (Exception e) {
            log.error("Failed to parse certificate status payload (messageId={}, deliveryTag={}): {}",
                    messageId, deliveryTag, payload, e);
            failureRecorder.recordFailure(messageId, null, null, 0L, payload, deliveryTag, consumerQueue, redelivered, e);
            throw new RuntimeException("Malformed certificate status message", e);
        }

        // Idempotency check — if already processed, mark duplicate and return
        Optional<InboxEvent> existingInbox = inboxRepository.findByEventId(event.eventId());
        if (existingInbox.isPresent() && !"FAILED".equalsIgnoreCase(existingInbox.get().getProcessingStatus())) {
            log.info("Duplicate event {} received for serial={}, deliveryTag={}, marking DUPLICATE",
                    event.eventId(), event.serialNumberHex(), deliveryTag);
            InboxEvent dup = existingInbox.get();
            dup.setProcessingStatus("DUPLICATE");
            dup.setProcessedAt(now);
            if (deliveryTag != null) dup.setDeliveryTag(deliveryTag);
            if (consumerQueue != null) dup.setConsumerQueue(consumerQueue);
            if (redelivered != null) dup.setRedelivered(redelivered);
            inboxRepository.save(dup);
            return;
        }

        try {
            InboxEvent inbox = existingInbox.orElseGet(() -> InboxEvent.builder()
                    .eventId(event.eventId())
                    .eventType("CertificateStatusChanged")
                    .certificateSerial(event.serialNumberHex())
                    .status(event.status().name())
                    .revocationReason(event.revocationReason())
                    .revocationTime(event.revocationTime())
                    .sequence(event.sequence())
                    .payload(payload)
                    .receivedAt(now)
                    .build());

            inbox.setProcessingStatus("RECEIVED");
            inbox.setDeliveryTag(deliveryTag);
            inbox.setConsumerQueue(consumerQueue);
            inbox.setRedelivered(redelivered);
            inbox.setErrorMessage(null);
            inbox = inboxRepository.save(inbox);

            // Apply status change — runs in the same transaction; rolls back together if it fails
            CertificateStatusUpdateCommand cmd = new CertificateStatusUpdateCommand(
                    event.eventId(),
                    event.occurredAt(),
                    event.issuerKeyHashHex(),
                    event.issuerNameHashHex(),
                    event.serialNumberHex(),
                    event.status(),
                    event.revocationTime(),
                    event.revocationReason(),
                    event.sequence()
            );
            boolean applied = statusService.applyStatusChange(cmd);
            inbox.setProcessedAt(Instant.now());
            inbox.setProcessingStatus(applied ? "PROCESSED" : "SKIPPED");
            inboxRepository.save(inbox);
        } catch (Exception e) {
            failureRecorder.recordFailure(
                    event.eventId(),
                    event.serialNumberHex(),
                    event.status() != null ? event.status().name() : null,
                    event.sequence(),
                    payload,
                    deliveryTag,
                    consumerQueue,
                    redelivered,
                    e
            );
            throw e;
        }
    }
}
