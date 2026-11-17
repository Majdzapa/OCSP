package com.company.incert.ocsp.messaging;

/**
 * Consumer interface for incoming certificate status change messages.
 */
public interface CertificateStatusConsumer {

    default void consume(String payload) {
        consume(payload, null, null, null, null);
    }

    default void consume(String payload, Long deliveryTag, String consumerQueue, Boolean redelivered) {
        consume(payload, null, deliveryTag, consumerQueue, redelivered);
    }

    /**
     * Ingests and processes a raw certificate status JSON payload along with broker delivery metadata.
     *
     * @param payload       raw JSON string from the message broker
     * @param messageId     AMQP messageId header (matches KMS outbox_event.event_id)
     * @param deliveryTag   RabbitMQ AMQP channel delivery tag
     * @param consumerQueue RabbitMQ queue name
     * @param redelivered   whether the broker marked the message as redelivered
     */
    void consume(String payload, String messageId, Long deliveryTag, String consumerQueue, Boolean redelivered);
}
