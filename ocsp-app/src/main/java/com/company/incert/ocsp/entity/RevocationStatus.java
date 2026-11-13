package com.company.incert.ocsp.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.HexFormat;

/**
 * Certificate status replicated from the KMS (table {@code revocation_status}).
 * Identified by the RFC 6960 CertID triple: issuerNameHash + issuerKeyHash + serialNumber.
 */
@Entity
@Table(name = "revocation_status",
    uniqueConstraints = {
        @UniqueConstraint(name = "uq_cert_id", columnNames = {"issuer_name_hash", "issuer_key_hash", "serial_number"}),
        @UniqueConstraint(name = "uq_source_event", columnNames = "source_event_id")
    })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RevocationStatus {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "issuer_name_hash", nullable = false, columnDefinition = "BINARY(20)")
    private byte[] issuerNameHash;

    @Column(name = "issuer_key_hash", nullable = false, columnDefinition = "BINARY(20)")
    private byte[] issuerKeyHash;

    @Column(name = "serial_number", nullable = false, columnDefinition = "VARBINARY(64)")
    private byte[] serialNumber;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 10)
    private CertificateStatus status;

    @Column(name = "revocation_time")
    private Instant revocationTime;

    @Column(name = "revocation_reason", length = 30)
    private String revocationReason;

    @Column(name = "this_update", nullable = false)
    private Instant thisUpdate;

    @Column(name = "source_event_id", nullable = false, length = 64)
    private String sourceEventId;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /** Monotonic per-certificate sequence from the KMS; protects against stale/out-of-order events. */
    @Column(name = "sequence", nullable = false)
    private long sequence;

    public String serialNumberHex() {
        return HexFormat.of().formatHex(serialNumber);
    }

    public RevocationReason revocationReasonEnum() {
        return RevocationReason.parse(revocationReason);
    }
}

