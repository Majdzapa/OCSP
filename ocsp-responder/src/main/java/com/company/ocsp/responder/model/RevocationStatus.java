package com.company.ocsp.responder.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.Instant;

/**
 * Durable, shared revocation status record — the source of truth for OCSP responses
 * within the OCSP subsystem.  Written exclusively by the {@code ocsp-sync-service};
 * the responder reads this table in read-only mode.
 *
 * <p>Keyed by the RFC 6960 {@code CertID} triple:
 * {@code (issuerNameHash, issuerKeyHash, serialNumber)}.
 */
@Entity
@Table(
    name = "revocation_status",
    uniqueConstraints = {
        @UniqueConstraint(
            name = "uq_cert_id",
            columnNames = {"issuer_name_hash", "issuer_key_hash", "serial_number"}
        ),
        @UniqueConstraint(
            name = "uq_source_event",
            columnNames = {"source_event_id"}
        )
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

    /**
     * SHA-1 hash of the issuer's distinguished name (20 bytes), as per RFC 6960.
     */
    @Column(name = "issuer_name_hash", nullable = false, length = 20,
            columnDefinition = "BINARY(20)")
    private byte[] issuerNameHash;

    /**
     * SHA-1 hash of the issuer's public key (20 bytes), as per RFC 6960.
     */
    @Column(name = "issuer_key_hash", nullable = false, length = 20,
            columnDefinition = "BINARY(20)")
    private byte[] issuerKeyHash;

    /**
     * Certificate serial number (up to 20 octets per RFC 5280 §4.1.2.2).
     */
    @Column(name = "serial_number", nullable = false, length = 64,
            columnDefinition = "VARBINARY(64)")
    private byte[] serialNumber;

    /**
     * Certificate status as understood by the OCSP protocol.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 10)
    private CertStatus status;

    /**
     * Time at which revocation took effect (null when status is GOOD).
     */
    @Column(name = "revocation_time")
    private Instant revocationTime;

    /**
     * RFC 5280 revocation reason code (e.g. "keyCompromise"), nullable.
     */
    @Column(name = "revocation_reason", length = 40)
    private String revocationReason;

    /**
     * The {@code thisUpdate} value that should be embedded in OCSP responses
     * built from this record — reflects when the OCSP status was last known good.
     */
    @Column(name = "this_update", nullable = false)
    private Instant thisUpdate;

    /**
     * Idempotency key sourced from the KMS domain event; prevents duplicate
     * processing on redelivery.
     */
    @Column(name = "source_event_id", nullable = false, length = 64)
    private String sourceEventId;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /** OCSP certificate status values per RFC 6960 §2.2. */
    public enum CertStatus {
        GOOD,
        REVOKED,
        UNKNOWN
    }
}
