package com.company.incert.ocsp.messaging;

/**
 * Consumer interface for incoming certificate status change messages.
 */
public interface CertificateStatusConsumer {

    default void consume(String payload) {
        consume(payload, null, null, null);
    }

    /**
     * Ingests and processes a raw certificate status JSON payload along with broker delivery metadata.
     *
     * @param payload       raw JSON string from the message broker
     * @param deliveryTag   RabbitMQ AMQP channel delivery tag (if delivered via AMQP)
     * @param consumerQueue RabbitMQ queue name
     * @param redelivered   whether the broker marked the message as redelivered
     */
    void consume(String payload, Long deliveryTag, String consumerQueue, Boolean redelivered);
}
