package com.company.incert.ocsp.messaging;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * RabbitMQ messaging adapter for receiving certificate status events.
 *
 * Listens to the AMQP queue and delegates message processing directly to {@link CertificateStatusConsumer}.
 * Decouples broker delivery mechanics from business and transactional inbox logic.
 *
 * If switching to Apache Kafka, AWS SQS, or GCP Pub/Sub in the future, simply implement
 * an equivalent consumer adapter invoking {@link CertificateStatusConsumer#consume(String)}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "ocsp.messaging.type", havingValue = "rabbitmq", matchIfMissing = true)
public class CertificateStatusListener {

    private final CertificateStatusConsumer consumer;

    @RabbitListener(queues = "${ocsp.rabbitmq.queue}")
    public void onMessage(String payload) {
        consumer.consume(payload);
    }
}
