package com.company.incert.ocsp.messaging;

import com.company.incert.ocsp.entity.InboxEvent;
import com.company.incert.ocsp.repository.InboxEventRepository;
import com.company.incert.ocsp.service.CertificateStatusService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;

/**
 * Consumes {@code CertificateStatusChanged} events from RabbitMQ,
 * records each event into the {@code inbox_event} table for auditing/idempotency,
 * and updates the replicated certificate status table.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateStatusListener {

    private final CertificateStatusService statusService;
    private final InboxEventRepository inboxRepository;
    private final ObjectMapper objectMapper;

    @RabbitListener(queues = "${ocsp.rabbitmq.queue}")
    public void onMessage(String payload) {
        Instant now = Instant.now();
        CertificateStatusEvent event;
        try {
            event = objectMapper.readValue(payload, CertificateStatusEvent.class);
        } catch (Exception e) {
            log.error("Failed to parse certificate status payload: {}", payload, e);
            throw new RuntimeException("Malformed certificate status message", e);
        }

        // Check if event was already recorded in inbox
        Optional<InboxEvent> existingInbox = inboxRepository.findByEventId(event.eventId());
        if (existingInbox.isPresent()) {
            log.info("Duplicate event {} received for serial={}, updating status to DUPLICATE",
                    event.eventId(), event.serialNumberHex());
            InboxEvent dup = existingInbox.get();
            dup.setProcessingStatus("DUPLICATE");
            dup.setProcessedAt(now);
            inboxRepository.save(dup);
            return;
        }

        // Save into inbox as RECEIVED
        InboxEvent inbox = InboxEvent.builder()
                .eventId(event.eventId())
                .eventType("CertificateStatusChanged")
                .certificateSerial(event.serialNumberHex())
                .status(event.status().name())
                .revocationReason(event.revocationReason())
                .revocationTime(event.revocationTime())
                .sequence(event.sequence())
                .payload(payload)
                .receivedAt(now)
                .processingStatus("RECEIVED")
                .build();
        inbox = inboxRepository.save(inbox);

        try {
            boolean applied = statusService.applyStatusChange(event);
            inbox.setProcessedAt(Instant.now());
            inbox.setProcessingStatus(applied ? "PROCESSED" : "SKIPPED");
            inboxRepository.save(inbox);
        } catch (Exception e) {
            log.error("Failed to apply certificate status change for event {}: {}", event.eventId(), e.getMessage(), e);
            inbox.setProcessedAt(Instant.now());
            inbox.setProcessingStatus("FAILED");
            inbox.setErrorMessage(e.getMessage());
            inboxRepository.save(inbox);
            throw new RuntimeException("Status change application failed", e);
        }
    }
}
