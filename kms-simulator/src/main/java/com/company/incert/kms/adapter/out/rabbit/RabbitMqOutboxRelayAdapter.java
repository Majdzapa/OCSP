package com.company.incert.kms.adapter.out.rabbit;

import com.company.incert.kms.adapter.out.jpa.OutboxEventJpaEntity;
import com.company.incert.kms.adapter.out.jpa.SpringDataOutboxRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Transactional outbox relay: polls unsent events and publishes to RabbitMQ.
 * Runs on a fixed delay (default 500ms). Marks events as sent after successful publish.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RabbitMqOutboxRelayAdapter {

    private final SpringDataOutboxRepository outboxRepo;
    private final RabbitTemplate rabbitTemplate;

    @Value("${kms.rabbitmq.exchange:incert.certificate.status}")
    private String exchange;

    @Value("${kms.rabbitmq.routing-key:incert.certificate.status.v1}")
    private String defaultRoutingKey;

    @Scheduled(fixedDelayString = "${kms.outbox.relay-delay-ms:500}")
    @Transactional
    public void relay() {
        List<OutboxEventJpaEntity> pending = outboxRepo.findBySentFalseOrderByCreatedAtAsc();
        if (pending.isEmpty()) return;

        log.debug("Outbox relay: {} pending events", pending.size());
        for (OutboxEventJpaEntity event : pending) {
            try {
                String routingKey = (event.getTopic() != null && !event.getTopic().isBlank())
                    ? event.getTopic() : defaultRoutingKey;

                rabbitTemplate.convertAndSend(exchange, routingKey, event.getPayload(), message -> {
                    message.getMessageProperties().setMessageId(event.getEventId());
                    message.getMessageProperties().setContentType("application/json");
                    if (event.getKafkaKey() != null) {
                        message.getMessageProperties().setHeader("partitionKey", event.getKafkaKey());
                    }
                    return message;
                });

                event.setSent(true);
                event.setSentAt(Instant.now());
                outboxRepo.save(event);
                log.debug("Relayed event to RabbitMQ: id={} exchange={} routingKey={}",
                    event.getEventId(), exchange, routingKey);
            } catch (Exception e) {
                log.error("Failed to relay outbox event id={}: {}", event.getEventId(), e.getMessage());
                // Will retry on next tick
                break;
            }
        }
    }
}
