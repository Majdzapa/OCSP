package com.company.incert.ocsp.signing.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Configured HSM slot / token / partition stored in {@code crypto_devices}.
 * <p>
 * Pattern 2 (Runtime Activation): zero PIN columns are stored in the database; operators unlock
 * devices interactively in memory at runtime via an Admin API / Console action.
 */
@Entity
@Table(name = "crypto_devices")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CryptoDeviceEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "device_id", nullable = false, unique = true, length = 100)
    private String deviceId;

    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "provider_id", nullable = false)
    private CryptoProviderEntity provider;

    @Column(name = "token_label", length = 150)
    private String tokenLabel;

    @Column(name = "slot_id")
    private Long slotId;

    @Column(name = "slot_list_index", nullable = false)
    @Builder.Default
    private int slotListIndex = 0;

    @Column(name = "pool_size", nullable = false)
    @Builder.Default
    private int poolSize = 4;

    @Column(name = "prehash_in_jvm", nullable = false)
    @Builder.Default
    private boolean prehashInJvm = false;

    @Column(name = "is_default", nullable = false)
    @Builder.Default
    private boolean defaultDevice = false;

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

