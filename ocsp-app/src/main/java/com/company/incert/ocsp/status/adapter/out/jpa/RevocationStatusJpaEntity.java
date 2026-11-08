package com.company.incert.ocsp.status.adapter.out.jpa;

import com.company.incert.ocsp.shared.domain.CertificateStatus;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

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
public class RevocationStatusJpaEntity {

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

    @Column(name = "sequence", nullable = false)
    private long sequence;
}

