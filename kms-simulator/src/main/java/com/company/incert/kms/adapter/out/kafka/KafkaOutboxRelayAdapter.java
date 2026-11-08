package com.company.incert.kms.adapter.out.kafka;

import com.company.incert.kms.adapter.out.jpa.OutboxEventJpaEntity;
import com.company.incert.kms.adapter.out.jpa.SpringDataOutboxRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Transactional outbox relay: polls unsent events and publishes to Kafka.
 * Runs on a fixed delay (default 500ms). Marks events as sent after successful publish.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class KafkaOutboxRelayAdapter {

    private final SpringDataOutboxRepository outboxRepo;
    private final KafkaTemplate<String, String> kafkaTemplate;

    @Scheduled(fixedDelayString = "${kms.outbox.relay-delay-ms:500}")
    @Transactional
    public void relay() {
        List<OutboxEventJpaEntity> pending = outboxRepo.findBySentFalseOrderByCreatedAtAsc();
        if (pending.isEmpty()) return;

        log.debug("Outbox relay: {} pending events", pending.size());
        for (OutboxEventJpaEntity event : pending) {
            try {
                kafkaTemplate.send(event.getTopic(), event.getKafkaKey(), event.getPayload())
                        .get(); // synchronous send — ensures durability
                event.setSent(true);
                event.setSentAt(Instant.now());
                outboxRepo.save(event);
                log.debug("Relayed event: id={} topic={}", event.getEventId(), event.getTopic());
            } catch (Exception e) {
                log.error("Failed to relay outbox event id={}: {}", event.getEventId(), e.getMessage());
                // Will retry on next tick
                break;
            }
        }
    }
}
