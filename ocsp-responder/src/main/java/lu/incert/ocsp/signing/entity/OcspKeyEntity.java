package lu.incert.ocsp.signing.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Cryptographic asymmetric key metadata persisted in {@code ocsp_keys}.
 * <p>
 * Extracted once from the PKCS#11 HSM token when the keypair is generated (or explicitly synced),
 * allowing UI queries, certificate public-key verification, and readiness checks to execute
 * without touching the hardware token. The private key itself never leaves the HSM token.
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

    @Column(name = "key_algorithm", nullable = false, length = 32)
    private String keyAlgorithm;

    @Column(name = "key_size", nullable = false)
    private int keySize;

    @Column(name = "public_key_pem", nullable = false, columnDefinition = "TEXT")
    private String publicKeyPem;

    @Column(name = "public_key_sha1", nullable = false, length = 64)
    private String publicKeySha1;

    @Column(name = "generated_at", nullable = false)
    @Builder.Default
    private Instant generatedAt = Instant.now();

    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private Instant createdAt = Instant.now();
}

