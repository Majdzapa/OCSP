package lu.incert.ocsp.signing.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * First-class OCSP Signer aggregate root stored in {@code ocsp_signers}.
 * Encapsulates the signer's relation to its cryptographic key ({@link OcspKeyEntity}),
 * ordered HSM Tokens ({@link OcspSignerTokenEntity}), signature algorithm,
 * generated PKCS#10 CSR, and imported X.509 signing certificate.
 */
@Entity
@Table(name = "ocsp_signers")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OcspSignerEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 100)
    private String code;

    @Column(nullable = false, length = 150)
    private String name;

    @Column(nullable = false, length = 32)
    @Builder.Default
    private String status = "DRAFT";

    @Column(name = "subject_dn", nullable = false, length = 500)
    private String subjectDn;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "key_id")
    private OcspKeyEntity key;

    @Column(name = "key_label", nullable = false, length = 150)
    private String keyLabel;

    @Column(name = "key_algorithm", nullable = false, length = 32)
    @Builder.Default
    private String keyAlgorithm = "RSA";

    @Column(name = "key_size", nullable = false)
    @Builder.Default
    private int keySize = 3072;

    @Column(name = "signature_algorithm", nullable = false, length = 64)
    @Builder.Default
    private String signatureAlgorithm = "SHA256withRSA";

    @Column(name = "csr_pem", columnDefinition = "TEXT")
    private String csrPem;

    @Column(name = "csr_generated_at")
    private Instant csrGeneratedAt;

    @Column(name = "certificate_pem", columnDefinition = "TEXT")
    private String certificatePem;

    @Column(name = "cert_subject_dn", length = 500)
    private String certSubjectDn;

    @Column(name = "cert_issuer_dn", length = 500)
    private String certIssuerDn;

    @Column(name = "cert_serial_number", length = 128)
    private String certSerialNumber;

    @Column(name = "cert_not_before")
    private Instant certNotBefore;

    @Column(name = "cert_not_after")
    private Instant certNotAfter;

    @Column(name = "signing_certificate_id")
    private Long signingCertificateId;

    @Column(nullable = false)
    @Builder.Default
    private boolean active = false;

    @Column(name = "activated_at")
    private Instant activatedAt;

    @OneToMany(mappedBy = "signer", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @OrderBy("priorityOrder ASC, id ASC")
    @Builder.Default
    private List<OcspSignerTokenEntity> tokens = new ArrayList<>();

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    @Builder.Default
    private Instant updatedAt = Instant.now();

    @PreUpdate
    void touchUpdatedAt() {
        this.updatedAt = Instant.now();
    }
}
