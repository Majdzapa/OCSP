package com.company.incert.kms.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * JPA entity representing a certificate managed in the KMS inventory.
 */
@Entity
@Table(name = "certificate",
        uniqueConstraints = @UniqueConstraint(name = "uq_serial", columnNames = "serial_number_hex"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Certificate {

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
    @Column(name = "status", nullable = false, length = 20)
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

    // Record-style accessor aliases for convenience & backwards compatibility
    public String serialNumberHex() { return serialNumberHex; }
    public String issuerDn() { return issuerDn; }
    public String issuerKeyHashHex() { return issuerKeyHashHex; }
    public String issuerNameHashHex() { return issuerNameHashHex; }
    public String subjectDn() { return subjectDn; }
    public Instant notBefore() { return notBefore; }
    public Instant notAfter() { return notAfter; }
    public CertificateStatus status() { return status; }
    public Instant revocationTime() { return revocationTime; }
    public RevocationReason revocationReason() { return revocationReason; }
    public String pemEncoded() { return pemEncoded; }
    public long sequence() { return sequence; }
}
