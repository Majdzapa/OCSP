package com.company.incert.ocsp.messaging;

import com.company.incert.ocsp.entity.InboxEvent;
import com.company.incert.ocsp.repository.InboxEventRepository;
import com.company.incert.ocsp.service.CertificateStatusService;
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
 * commit or neither does.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateStatusConsumerService implements CertificateStatusConsumer {

    private final CertificateStatusService statusService;
    private final InboxEventRepository inboxRepository;
    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public void consume(String payload) {
        Instant now = Instant.now();
        CertificateStatusEvent event;
        try {
            event = objectMapper.readValue(payload, CertificateStatusEvent.class);
        } catch (Exception e) {
            log.error("Failed to parse certificate status payload: {}", payload, e);
            throw new RuntimeException("Malformed certificate status message", e);
        }

        // Idempotency check — if already processed, mark duplicate and return
        Optional<InboxEvent> existingInbox = inboxRepository.findByEventId(event.eventId());
        if (existingInbox.isPresent()) {
            log.info("Duplicate event {} received for serial={}, marking DUPLICATE",
                    event.eventId(), event.serialNumberHex());
            InboxEvent dup = existingInbox.get();
            dup.setProcessingStatus("DUPLICATE");
            dup.setProcessedAt(now);
            inboxRepository.save(dup);
            return;
        }

        // Record in inbox as RECEIVED — same transaction as status update below
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

        // Apply status change — runs in the same transaction; rolls back together if it fails
        boolean applied = statusService.applyStatusChange(event);
        inbox.setProcessedAt(Instant.now());
        inbox.setProcessingStatus(applied ? "PROCESSED" : "SKIPPED");
        inboxRepository.save(inbox);
    }
}

