package com.company.incert.ocsp.messaging;

import com.company.incert.ocsp.service.CertificateStatusService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

/**
 * Consumes {@code CertificateStatusChanged} events from RabbitMQ and updates the status table.
 * Ordering across instances is protected by the monotonic {@code sequence} in each event.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateStatusListener {

    private final CertificateStatusService statusService;
    private final ObjectMapper objectMapper;

    @RabbitListener(queues = "${ocsp.rabbitmq.queue}")
    public void onMessage(String payload) {
        try {
            CertificateStatusEvent event = objectMapper.readValue(payload, CertificateStatusEvent.class);
            statusService.applyStatusChange(event);
        } catch (Exception e) {
            log.error("Failed to process certificate status message: {}", e.getMessage(), e);
            throw new RuntimeException("Message processing failed (will retry / dead-letter)", e);
        }
    }
}

