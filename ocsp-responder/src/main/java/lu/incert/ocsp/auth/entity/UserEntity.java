package lu.incert.ocsp.auth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserEntity {

    @Id
    @Column(length = 36, nullable = false, updatable = false)
    private String id;

    @Column(name = "external_id", unique = true, length = 255)
    private String externalId;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_source", nullable = false, length = 20)
    private AuthSource authSource;

    @Column(nullable = false, unique = true, length = 100)
    private String username;

    @Column(length = 255)
    private String email;

    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    private boolean emailVerified = false;

    @Column(name = "full_name", length = 255)
    private String fullName;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    /** BCrypt hash for LOCAL users only; always {@code null} for KEYCLOAK users. */
    @Column(name = "password_hash", length = 255)
    private String passwordHash;

    @Column(name = "tenant_id", nullable = false, length = 100)
    @Builder.Default
    private String tenantId = "default";

    @Column(name = "preferences_json", columnDefinition = "TEXT")
    private String preferencesJson;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<RoleEntity> roles = new HashSet<>();

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        if (this.id == null) {
            this.id = UUID.randomUUID().toString();
        }
        if (this.tenantId == null || this.tenantId.isBlank()) {
            this.tenantId = "default";
        }
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = Instant.now();
    }

    public boolean isDeleted() {
        return deletedAt != null;
    }
}
