-- =============================================================================
-- Incert OCSP Subsystem — Flyway Migration V9: Dual-Mode Identity (UUID PK)
-- Supports SELF_MANAGEMENT (LOCAL) and KEYCLOAK (read-only identity replica)
-- =============================================================================

DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id CHAR(36) NOT NULL PRIMARY KEY,
    external_id VARCHAR(255) NULL UNIQUE COMMENT 'Keycloak subject (sub) in KEYCLOAK mode',
    auth_source VARCHAR(20) NOT NULL COMMENT 'LOCAL or KEYCLOAK',
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    full_name VARCHAR(255) NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    password_hash VARCHAR(255) NULL COMMENT 'BCrypt hash for LOCAL users only; always NULL for KEYCLOAK',
    tenant_id VARCHAR(100) NOT NULL DEFAULT 'default',
    preferences_json TEXT NULL,
    deleted_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_users_external_id (external_id),
    INDEX idx_users_email (email),
    INDEX idx_users_auth_source (auth_source),
    INDEX idx_users_deleted_at (deleted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE user_roles (
    user_id CHAR(36) NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS identity_outbox (
    id CHAR(36) NOT NULL PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    operation VARCHAR(50) NOT NULL,
    payload TEXT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    last_error VARCHAR(1000) NULL,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_identity_outbox_processed (processed, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

