package com.company.incert.ocsp.sync.adapter.in;

import com.company.incert.ocsp.shared.domain.CertificateStatus;
import com.company.incert.ocsp.shared.domain.RevocationReason;
import com.company.incert.ocsp.sync.application.port.in.ApplyStatusChangeUseCase;
import com.company.incert.ocsp.sync.domain.StatusChangeCommand;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.HexFormat;

/**
 * Kafka consumer for incert.certificate.status.v1 topic.
 * Driving adapter: maps Kafka record → ApplyStatusChangeUseCase command.
 * Manual offset commit after DB transaction commits.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateStatusKafkaListener {

    private final ApplyStatusChangeUseCase applyStatusChangeUseCase;
    private final ObjectMapper objectMapper;

    @KafkaListener(
        topics = "${ocsp.kafka.topic:incert.certificate.status.v1}",
        groupId = "${ocsp.kafka.consumer-group:ocsp-sync}",
        containerFactory = "ocspKafkaListenerContainerFactory"
    )
    public void onMessage(ConsumerRecord<String, String> record, Acknowledgment ack) {
        log.debug("Received Kafka message: topic={} partition={} offset={}",
            record.topic(), record.partition(), record.offset());
        try {
            StatusChangeCommand cmd = parseCommand(record.value());
            applyStatusChangeUseCase.apply(cmd);
            if (ack != null) {
                ack.acknowledge();
            }
            log.debug("Committed offset: partition={} offset={}", record.partition(), record.offset());
        } catch (Exception e) {
            log.error("Failed to process Kafka message: topic={} partition={} offset={} error={}",
                record.topic(), record.partition(), record.offset(), e.getMessage(), e);
            throw new RuntimeException("Message processing failed", e);
        }
    }

    private StatusChangeCommand parseCommand(String json) throws Exception {
        JsonNode root = objectMapper.readTree(json);

        String eventId = root.path("eventId").asText();
        String statusStr = root.path("status").asText("GOOD");
        CertificateStatus status = CertificateStatus.valueOf(statusStr);

        String reasonStr = root.path("revocationReason").asText(null);
        RevocationReason reason = null;
        if (reasonStr != null && !reasonStr.isBlank() && !reasonStr.equals("null")) {
            try {
                reason = RevocationReason.valueOf(reasonStr);
            } catch (Exception e) {
                /* unknown reason */
            }
        }

        Instant revocationTime = parseInstant(root.path("revocationTime"));
        Instant occurredAt = parseInstant(root.path("occurredAt"));
        if (occurredAt == null) {
            occurredAt = Instant.now();
        }
        long sequence = root.path("sequence").asLong(0);

        HexFormat hex = HexFormat.of();
        byte[] issuerKeyHash = hex.parseHex(root.path("issuerKeyHashHex").asText());
        byte[] issuerNameHash = hex.parseHex(root.path("issuerNameHashHex").asText());
        byte[] serialNumber = hex.parseHex(root.path("serialNumberHex").asText());

        return new StatusChangeCommand(
            eventId, issuerNameHash, issuerKeyHash, serialNumber,
            status, revocationTime, reason, occurredAt, sequence
        );
    }

    private Instant parseInstant(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        if (node.isNumber()) {
            double seconds = node.asDouble();
            long secs = (long) seconds;
            long nanos = (long) Math.round((seconds - secs) * 1_000_000_000.0);
            return Instant.ofEpochSecond(secs, nanos);
        }
        String text = node.asText();
        if (text == null || text.isBlank() || text.equals("null")) {
            return null;
        }
        try {
            return Instant.parse(text);
        } catch (Exception e) {
            try {
                double seconds = Double.parseDouble(text);
                long secs = (long) seconds;
                long nanos = (long) Math.round((seconds - secs) * 1_000_000_000.0);
                return Instant.ofEpochSecond(secs, nanos);
            } catch (Exception ex) {
                return null;
            }
        }
    }
}

