package com.company.incert.ocsp.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

import java.time.Instant;

/**
 * Transactional Inbox entity storing all certificate status change events received from RabbitMQ.
 * Enables guaranteed at-least-once processing, deduplication, and complete audit reconciliation.
 */
@Entity
@Table(name = "inbox_event")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class InboxEvent {

    @Id
    @Column(name = "event_id", nullable = false, length = 64)
    private String eventId;

    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    @Column(name = "certificate_serial", nullable = false, length = 128)
    private String certificateSerial;

    @Column(name = "status", nullable = false, length = 32)
    private String status;

    @Column(name = "revocation_reason", length = 64)
    private String revocationReason;

    @Column(name = "revocation_time")
    private Instant revocationTime;

    @Column(name = "sequence", nullable = false)
    private long sequence;

    @Column(name = "payload", columnDefinition = "TEXT")
    private String payload;

    @Column(name = "received_at", nullable = false)
    private Instant receivedAt;

    @Column(name = "processed_at")
    private Instant processedAt;

    @Column(name = "processing_status", nullable = false, length = 32)
    private String processingStatus; // RECEIVED, PROCESSED, DUPLICATE, SKIPPED, FAILED

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;
}

