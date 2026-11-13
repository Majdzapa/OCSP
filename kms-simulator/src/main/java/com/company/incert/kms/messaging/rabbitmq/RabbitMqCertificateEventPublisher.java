package com.company.incert.kms.messaging.rabbitmq;

import com.company.incert.kms.messaging.CertificateEventPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * RabbitMQ adapter implementing {@link CertificateEventPublisher}.
 * Publishes events to the configured RabbitMQ direct exchange.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "kms.messaging.type", havingValue = "rabbitmq", matchIfMissing = true)
public class RabbitMqCertificateEventPublisher implements CertificateEventPublisher {

    private final RabbitTemplate rabbitTemplate;

    @Value("${kms.rabbitmq.exchange:incert.certificate.status}")
    private String exchange;

    @Value("${kms.rabbitmq.routing-key:incert.certificate.status.v1}")
    private String defaultRoutingKey;

    @Override
    public void publish(String eventId, String topic, String partitionKey, String jsonPayload) {
        String routingKey = (topic != null && !topic.isBlank()) ? topic : defaultRoutingKey;

        rabbitTemplate.convertAndSend(exchange, routingKey, jsonPayload, message -> {
            message.getMessageProperties().setMessageId(eventId);
            message.getMessageProperties().setContentType("application/json");
            if (partitionKey != null) {
                message.getMessageProperties().setHeader("partitionKey", partitionKey);
            }
            return message;
        });

        log.debug("Published event to RabbitMQ: id={} exchange={} routingKey={}",
                eventId, exchange, routingKey);
    }
}
