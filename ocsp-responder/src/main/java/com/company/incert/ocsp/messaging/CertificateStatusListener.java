package com.company.incert.ocsp.messaging;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.support.AmqpHeaders;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.messaging.handler.annotation.Header;
import org.springframework.stereotype.Component;

/**
 * RabbitMQ messaging adapter for receiving certificate status events.
 * Captures AMQP delivery metadata (deliveryTag, consumerQueue, redelivered)
 * so every processed or failed message can be traced back to its RabbitMQ delivery.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "ocsp.messaging.type", havingValue = "rabbitmq", matchIfMissing = true)
public class CertificateStatusListener {

    private final CertificateStatusConsumer consumer;

    @RabbitListener(queues = "${ocsp.rabbitmq.queue}")
    public void onMessage(
            String payload,
            @Header(name = AmqpHeaders.DELIVERY_TAG, required = false) Long deliveryTag,
            @Header(name = AmqpHeaders.CONSUMER_QUEUE, required = false) String consumerQueue,
            @Header(name = AmqpHeaders.REDELIVERED, required = false) Boolean redelivered) {
        consumer.consume(payload, deliveryTag, consumerQueue, redelivered);
    }
}
