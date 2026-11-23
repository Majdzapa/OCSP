package com.company.incert.ocsp.trust.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Trusted Certificate Authority (CA) certificate stored in the database and hot-reloaded
 * into the in-memory mTLS truststore without restarting the application.
 */
@Entity
@Table(name = "trusted_cas")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TrustedCaEntity {

    @Id
    @Column(name = "id", length = 36, nullable = false)
    private String id;

    @Column(name = "alias", length = 128, nullable = false, unique = true)
    private String alias;

    @Column(name = "subject_dn", length = 512, nullable = false)
    private String subjectDn;

    @Column(name = "issuer_dn", length = 512, nullable = false)
    private String issuerDn;

    @Column(name = "serial_number_hex", length = 128, nullable = false)
    private String serialNumberHex;

    @Column(name = "fingerprint_sha256", length = 64, nullable = false, unique = true)
    private String fingerprintSha256;

    @Lob
    @Column(name = "certificate_pem", nullable = false, columnDefinition = "TEXT")
    private String certificatePem;

    @Column(name = "not_before")
    private Instant notBefore;

    @Column(name = "not_after")
    private Instant notAfter;

    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}

