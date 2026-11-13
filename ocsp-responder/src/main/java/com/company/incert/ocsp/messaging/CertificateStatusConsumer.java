package com.company.incert.ocsp.messaging;

/**
 * Consumer interface for incoming certificate status change messages.
 *
 * Decouples payload ingestion, idempotency deduplication, and transactional inbox
 * recording from specific message broker implementations (RabbitMQ, Kafka, AWS SQS, etc.).
 *
 * To switch messaging brokers, simply implement an adapter that receives the broker
 * message and calls {@link #consume(String)}.
 */
public interface CertificateStatusConsumer {

    /**
     * Ingests and processes a raw certificate status JSON payload.
     * Records the event in the transactional inbox, guarantees idempotency,
     * and updates the local revocation status database.
     *
     * @param payload raw JSON string from the message broker
     */
    void consume(String payload);
}
