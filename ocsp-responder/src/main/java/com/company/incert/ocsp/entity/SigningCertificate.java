package com.company.incert.ocsp.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Registry of OCSP response signing certificates.
 * Exactly one certificate is active at any given time to sign responses.
 */
@Entity
@Table(name = "signing_certificates", indexes = {
    @Index(name = "idx_sign_cert_active", columnList = "active")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SigningCertificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String alias;

    @Column(name = "key_label", nullable = false, length = 100)
    private String keyLabel;

    @Lob
    @Column(name = "certificate_pem", nullable = false, columnDefinition = "MEDIUMTEXT")
    private String certificatePem;

    @Column(name = "subject_dn", nullable = false, length = 500)
    private String subjectDn;

    @Column(name = "issuer_dn", nullable = false, length = 500)
    private String issuerDn;

    @Column(name = "serial_number", nullable = false, length = 100)
    private String serialNumber;

    @Column(name = "not_before")
    private Instant notBefore;

    @Column(name = "not_after")
    private Instant notAfter;

    @Column(name = "signature_algorithm", nullable = false, length = 50)
    private String signatureAlgorithm;

    @Column(nullable = false)
    private boolean active;

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(name = "activated_at")
    private Instant activatedAt;
}

