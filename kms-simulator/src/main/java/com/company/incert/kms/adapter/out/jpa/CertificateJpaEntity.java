package com.company.incert.kms.adapter.out.jpa;

import com.company.incert.kms.domain.CertificateStatus;
import com.company.incert.kms.domain.RevocationReason;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "certificate",
        uniqueConstraints = @UniqueConstraint(name = "uq_serial", columnNames = "serial_number_hex"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertificateJpaEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "serial_number_hex", nullable = false, length = 128)
    private String serialNumberHex;

    @Column(name = "issuer_dn", nullable = false, length = 512)
    private String issuerDn;

    @Column(name = "issuer_key_hash_hex", nullable = false, length = 40)
    private String issuerKeyHashHex;

    @Column(name = "issuer_name_hash_hex", nullable = false, length = 40)
    private String issuerNameHashHex;

    @Column(name = "subject_dn", nullable = false, length = 512)
    private String subjectDn;

    @Column(name = "not_before", nullable = false)
    private Instant notBefore;

    @Column(name = "not_after", nullable = false)
    private Instant notAfter;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 10)
    private CertificateStatus status;

    @Column(name = "revocation_time")
    private Instant revocationTime;

    @Enumerated(EnumType.STRING)
    @Column(name = "revocation_reason", length = 30)
    private RevocationReason revocationReason;

    @Column(name = "pem_encoded", columnDefinition = "MEDIUMTEXT")
    private String pemEncoded;

    @Column(name = "sequence", nullable = false)
    private long sequence;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
