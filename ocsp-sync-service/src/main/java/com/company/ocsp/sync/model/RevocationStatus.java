package com.company.ocsp.sync.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Mirrors the {@code revocation_status} table.  Written exclusively by this
 * service; the responder has read-only access.
 */
@Entity
@Table(
    name = "revocation_status",
    uniqueConstraints = {
        @UniqueConstraint(name = "uq_cert_id",
            columnNames = {"issuer_name_hash", "issuer_key_hash", "serial_number"}),
        @UniqueConstraint(name = "uq_source_event",
            columnNames = {"source_event_id"})
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RevocationStatus {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "issuer_name_hash", nullable = false, length = 20,
            columnDefinition = "BINARY(20)")
    private byte[] issuerNameHash;

    @Column(name = "issuer_key_hash", nullable = false, length = 20,
            columnDefinition = "BINARY(20)")
    private byte[] issuerKeyHash;

    @Column(name = "serial_number", nullable = false, length = 64,
            columnDefinition = "VARBINARY(64)")
    private byte[] serialNumber;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 10)
    private CertStatus status;

    @Column(name = "revocation_time")
    private Instant revocationTime;

    @Column(name = "revocation_reason", length = 40)
    private String revocationReason;

    @Column(name = "this_update", nullable = false)
    private Instant thisUpdate;

    @Column(name = "source_event_id", nullable = false, length = 64)
    private String sourceEventId;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public enum CertStatus {
        GOOD, REVOKED, UNKNOWN
    }
}
