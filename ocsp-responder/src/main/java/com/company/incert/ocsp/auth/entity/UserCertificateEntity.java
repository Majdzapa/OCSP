package com.company.incert.ocsp.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * X.509 certificate assigned to a user for optional mTLS client-certificate authentication.
 */
@Entity
@Table(name = "user_certificates")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserCertificateEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private UserEntity user;

    @Column(name = "serial_number_hex", length = 128, nullable = false)
    private String serialNumberHex;

    @Column(name = "fingerprint_sha256", length = 64, nullable = false, unique = true)
    private String fingerprintSha256;

    @Column(name = "subject_dn", length = 512, nullable = false)
    private String subjectDn;

    @Column(name = "issuer_dn", length = 512, nullable = false)
    private String issuerDn;

    @Lob
    @Column(name = "certificate_pem", nullable = false, columnDefinition = "TEXT")
    private String certificatePem;

    @Column(name = "not_before")
    private Instant notBefore;

    @Column(name = "not_after")
    private Instant notAfter;

    @Column(name = "revoked", nullable = false)
    @Builder.Default
    private boolean revoked = false;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}

