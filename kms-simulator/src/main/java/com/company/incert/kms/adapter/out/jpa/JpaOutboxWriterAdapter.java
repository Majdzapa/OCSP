package com.company.incert.kms.adapter.out.jpa;

import com.company.incert.kms.application.port.out.OutboxWriter;
import com.company.incert.kms.domain.CertificateStatusChangedEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;

@Slf4j
@RequiredArgsConstructor
public class JpaOutboxWriterAdapter implements OutboxWriter {

    private final SpringDataOutboxRepository outboxRepo;
    private final ObjectMapper objectMapper;

    private static final String TOPIC = "incert.certificate.status.v1";

    @Override
    public void write(CertificateStatusChangedEvent event) {
        try {
            String payload = objectMapper.writeValueAsString(event);
            String kafkaKey = event.issuerKeyHashHex() + ":" + event.serialNumberHex();
            OutboxEventJpaEntity entity = OutboxEventJpaEntity.builder()
                    .eventId(event.eventId())
                    .topic(TOPIC)
                    .kafkaKey(kafkaKey)
                    .payload(payload)
                    .createdAt(Instant.now())
                    .sent(false)
                    .build();
            outboxRepo.save(entity);
            log.debug("Outbox event written: id={} key={}", event.eventId(), kafkaKey);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize outbox event", e);
        }
    }
}
