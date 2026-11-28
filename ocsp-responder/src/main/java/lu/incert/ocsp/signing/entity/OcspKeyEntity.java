package lu.incert.ocsp.signing.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Cryptographic asymmetric key metadata persisted in {@code ocsp_keys}.
 * <p>
 * Supports the EJBCA zero-downtime key-rotation model: an {@link OcspSignerEntity} may own
 * multiple keys (active key + next/staged key + retired keys), each carrying its own CSR and
 * CA-signed X.509 certificate, while at most ONE key is {@code active} per Signer and per HSM Token.
 * The private key itself never leaves the HSM token.
 */
@Entity
@Table(name = "ocsp_keys")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OcspKeyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "key_label", nullable = false, unique = true, length = 150)
    private String keyLabel;

    @Column(name = "cka_id_hex", length = 300)
    private String ckaIdHex;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "token_device_id")
    private CryptoDeviceEntity tokenDevice;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "signer_id")
    private OcspSignerEntity signer;

    @Column(name = "key_algorithm", nullable = false, length = 32)
    private String keyAlgorithm;

    @Column(name = "key_size", nullable = false)
    private int keySize;

    @Column(name = "public_key_pem", nullable = false, columnDefinition = "TEXT")
    private String publicKeyPem;

    @Column(name = "public_key_sha1", nullable = false, length = 64)
    private String publicKeySha1;

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

    @Column(name = "active", nullable = false)
    @Builder.Default
    private boolean active = false;

    @Column(name = "activated_at")
    private Instant activatedAt;

    @Column(name = "generated_at", nullable = false)
    @Builder.Default
    private Instant generatedAt = Instant.now();

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();
}
