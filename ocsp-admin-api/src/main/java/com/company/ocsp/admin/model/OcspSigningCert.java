package com.company.ocsp.admin.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

/**
 * Delegated OCSP signing certificate lifecycle record.
 * Read by the admin dashboard to show days-remaining and rotation status.
 */
@Entity
@Table(name = "ocsp_signing_cert")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OcspSigningCert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "serial_number", nullable = false, columnDefinition = "VARBINARY(64)")
    private byte[] serialNumber;

    @Column(name = "not_before", nullable = false)
    private Instant notBefore;

    @Column(name = "not_after", nullable = false)
    private Instant notAfter;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive;

    @Column(name = "kms_key_reference", nullable = false, length = 128)
    private String kmsKeyReference;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
