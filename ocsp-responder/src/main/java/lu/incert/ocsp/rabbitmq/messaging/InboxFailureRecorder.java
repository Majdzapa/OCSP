package lu.incert.ocsp.rabbitmq.messaging;

import lu.incert.ocsp.rabbitmq.entity.InboxEvent;
import lu.incert.ocsp.rabbitmq.repository.InboxEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Persists FAILED inbox records in an independent transaction so broker failures
 * (with RabbitMQ deliveryTag, queue, redelivered flag, and errorMessage) remain visible
 * in the audit log even when the main consumer transaction rolls back to trigger DLQ routing.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class InboxFailureRecorder {

    private final InboxEventRepository inboxRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(
            String eventId,
            String certificateSerial,
            String status,
            long sequence,
            String payload,
            Long deliveryTag,
            String consumerQueue,
            Boolean redelivered,
            Throwable error) {
        String id = (eventId != null && !eventId.isBlank()) ? eventId : "failed-" + UUID.randomUUID();
        String serial = (certificateSerial != null && !certificateSerial.isBlank()) ? certificateSerial : "UNKNOWN";
        String certStatus = (status != null && !status.isBlank()) ? status : "UNKNOWN";
        Instant now = Instant.now();

        InboxEvent failed = InboxEvent.builder()
                .eventId(id)
                .eventType("CertificateStatusChanged")
                .certificateSerial(serial)
                .status(certStatus)
                .sequence(sequence)
                .payload(payload)
                .receivedAt(now)
                .processedAt(now)
                .processingStatus("FAILED")
                .errorMessage(error != null ? error.getMessage() : "Unknown processing error")
                .deliveryTag(deliveryTag)
                .consumerQueue(consumerQueue)
                .redelivered(redelivered)
                .build();

        inboxRepository.save(failed);
        log.warn("Recorded FAILED inbox event: eventId={} deliveryTag={} queue={} redelivered={}",
                id, deliveryTag, consumerQueue, redelivered);
    }
}

