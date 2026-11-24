package lu.incert.ocsp.signing.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Vendor PKCS#11 cryptographic driver + JNI wrapper configuration stored in {@code crypto_providers}.
 */
@Entity
@Table(name = "crypto_providers")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CryptoProviderEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String code;

    @Column(nullable = false, length = 150)
    private String name;

    @Column(name = "wrapper_type", nullable = false, length = 40)
    @Builder.Default
    private String wrapperType = "PKCS11J";

    @Column(name = "library_path", nullable = false, length = 500)
    private String libraryPath;

    @Column(name = "library_wrapper_path", nullable = false, length = 500)
    @Builder.Default
    private String libraryWrapperPath = "/opt/pkcs11j/libpkcs11wrapper.so";

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

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

