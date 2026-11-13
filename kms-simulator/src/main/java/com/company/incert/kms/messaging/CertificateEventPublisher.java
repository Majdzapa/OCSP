package com.company.incert.kms.messaging;

/**
 * Pluggable messaging interface for publishing certificate lifecycle events.
 *
 * Decouples the application (services & transactional outbox relay) from any specific
 * message broker technology.
 *
 * Current default implementation is RabbitMQ ({@link com.company.incert.kms.messaging.rabbitmq.RabbitMqCertificateEventPublisher}).
 * To switch to Apache Kafka, AWS SQS, or GCP Pub/Sub, simply provide an alternative
 * adapter implementing this interface.
 */
public interface CertificateEventPublisher {

    /**
     * Publishes an event payload to the destination message broker.
     *
     * @param eventId unique event identifier for tracing and idempotency
     * @param topic destination topic, queue, or routing key
     * @param partitionKey partitioning key (e.g. issuerKeyHash:serialNumberHex)
     * @param jsonPayload serialized JSON message body
     */
    void publish(String eventId, String topic, String partitionKey, String jsonPayload);
}

