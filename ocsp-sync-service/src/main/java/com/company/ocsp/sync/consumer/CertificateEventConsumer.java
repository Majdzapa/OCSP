package com.company.ocsp.sync.consumer;

import com.company.ocsp.sync.dto.CertificateEventDto;
import com.company.ocsp.sync.model.CertEventAudit;
import com.company.ocsp.sync.repository.CertEventAuditRepository;
import com.company.ocsp.sync.service.CertificateEventProcessor;
import com.rabbitmq.client.Channel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.support.AmqpHeaders;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * RabbitMQ consumer for KMS certificate domain events.
 *
 * <p>Uses manual acknowledgment:
 * <ul>
 *   <li>ack after the MariaDB transaction commits successfully.
 *   <li>nack (requeue=false) on failure, sending the message to the DLQ
 *       ({@code ocsp.status.sync.dlq}) for investigation and replay.
 * </ul>
 *
 * <p>An audit row is inserted before processing begins so that even messages
 * that fail mid-flight are traceable.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateEventConsumer {

    private final CertificateEventProcessor processor;
    private final CertEventAuditRepository  auditRepository;

    @RabbitListener(
        queues     = "${ocsp.rabbitmq.status-sync-queue:ocsp.status.sync}",
        ackMode    = "MANUAL",
        containerFactory = "rabbitListenerContainerFactory"
    )
    public void onCertificateEvent(
            CertificateEventDto event,
            Channel channel,
            @Header(AmqpHeaders.DELIVERY_TAG) long deliveryTag) {

        log.info("Received certificate event: id={} type={}",
            event.getEventId(), event.getEventType());

        // Insert RECEIVED audit row (for traceability even on failure)
        insertAuditReceived(event);

        try {
            processor.process(event);
            channel.basicAck(deliveryTag, false);
            log.debug("Acked event: id={}", event.getEventId());
        } catch (Exception e) {
            log.error("Failed to process event id={}: {}", event.getEventId(), e.getMessage(), e);
            processor.markAuditFailed(event.getEventId(), e.getMessage());
            try {
                // nack, do not requeue — send to DLQ for ops review
                channel.basicNack(deliveryTag, false, false);
            } catch (Exception nackEx) {
                log.error("Failed to nack message id={}", event.getEventId(), nackEx);
            }
        }
    }

    private void insertAuditReceived(CertificateEventDto event) {
        try {
            CertEventAudit audit = CertEventAudit.builder()
                .eventId(event.getEventId())
                .eventType(event.getEventType())
                .serialNumber(Hex.decode(event.getSerialNumberHex()))
                .receivedAt(Instant.now())
                .status(CertEventAudit.ProcessingStatus.RECEIVED)
                .build();
            auditRepository.save(audit);
        } catch (Exception e) {
            // Duplicate key on redelivery → idempotent, ignore
            log.debug("Audit row already exists for eventId={} (likely redelivery)",
                event.getEventId());
        }
    }
}
