package com.company.ocsp.admin.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

/**
 * Audit record for every KMS domain event processed by the sync service.
 *
 * <p>This entity is a <em>read-only</em> projection of the
 * {@code cert_event_audit} table, owned by the sync service.  The admin API
 * only reads from it — never writes.
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

    @Column(name = "serial_number", nullable = false, columnDefinition = "VARBINARY(64)")
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
