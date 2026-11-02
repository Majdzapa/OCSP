package com.company.ocsp.sync.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Audit record for every KMS domain event processed by the sync service.
 * Used by the reconciliation job and the React admin console's audit viewer.
 */
@Entity
@Table(name = "cert_event_audit")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertEventAudit {

    @Id
    @Column(name = "event_id", nullable = false, length = 64)
    private String eventId;

    @Column(name = "event_type", nullable = false, length = 40)
    private String eventType;

    @Column(name = "serial_number", nullable = false, length = 64,
            columnDefinition = "VARBINARY(64)")
    private byte[] serialNumber;

    @Column(name = "received_at", nullable = false, updatable = false)
    private Instant receivedAt;

    @Column(name = "processed_at")
    private Instant processedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private ProcessingStatus status;

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    public enum ProcessingStatus {
        RECEIVED, PROCESSED, FAILED
    }
}
