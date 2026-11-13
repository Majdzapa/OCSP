package com.company.incert.kms.service;

import com.company.incert.kms.entity.OutboxEvent;
import com.company.incert.kms.messaging.CertificateEventPublisher;
import com.company.incert.kms.repository.OutboxEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Transactional outbox relay: polls unsent events and publishes via {@link CertificateEventPublisher}.
 *
 * Runs on a fixed delay (default 500ms). Marks events as sent after successful publish.
 * Completely decoupled from any specific messaging broker.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OutboxRelayService {

    private final OutboxEventRepository outboxRepo;
    private final CertificateEventPublisher eventPublisher;

    @Scheduled(fixedDelayString = "${kms.outbox.relay-delay-ms:500}")
    @Transactional
    public void relay() {
        List<OutboxEvent> pending = outboxRepo.findBySentFalseOrderByCreatedAtAsc();
        if (pending.isEmpty()) return;

        log.debug("Outbox relay: {} pending events", pending.size());
        for (OutboxEvent event : pending) {
            try {
                eventPublisher.publish(
                        event.getEventId(),
                        event.getTopic(),
                        event.getEventKey(),
                        event.getPayload()
                );

                event.setSent(true);
                event.setSentAt(Instant.now());
                outboxRepo.save(event);
                log.debug("Relayed event: id={} topic={}", event.getEventId(), event.getTopic());
            } catch (Exception e) {
                log.error("Failed to relay outbox event id={}: {}", event.getEventId(), e.getMessage());
                // Stop batch on error to preserve strict ordering; retry on next tick
                break;
            }
        }
    }
}

