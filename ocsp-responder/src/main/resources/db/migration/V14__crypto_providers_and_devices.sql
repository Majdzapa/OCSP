-- =============================================================================
-- Incert OCSP Subsystem — Flyway Migration V14: Cryptographic Providers & Devices
-- Stores HSM driver + JNI wrapper configs (crypto_providers) and tokens/slots
-- (crypto_devices) in MariaDB with ZERO PIN columns (Pattern 2 Runtime Activation).
-- =============================================================================

CREATE TABLE IF NOT EXISTS crypto_providers (
    id                   BIGINT AUTO_INCREMENT PRIMARY KEY,
    code                 VARCHAR(64)  NOT NULL,
    name                 VARCHAR(150) NOT NULL,
    wrapper_type         VARCHAR(40)  NOT NULL DEFAULT 'PKCS11J',
    library_path         VARCHAR(500) NOT NULL,
    library_wrapper_path VARCHAR(500) NOT NULL DEFAULT 'embedded',
    enabled              BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at           DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_crypto_providers_code UNIQUE (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS crypto_devices (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    device_id       VARCHAR(100) NOT NULL,
    provider_id     BIGINT       NOT NULL,
    token_label     VARCHAR(150) NULL,
    slot_id         BIGINT       NULL,
    slot_list_index INT          NOT NULL DEFAULT 0,
    pool_size       INT          NOT NULL DEFAULT 4,
    prehash_in_jvm  BOOLEAN      NOT NULL DEFAULT FALSE,
    is_default      BOOLEAN      NOT NULL DEFAULT FALSE,
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_crypto_devices_device_id UNIQUE (device_id),
    CONSTRAINT fk_crypto_devices_provider FOREIGN KEY (provider_id)
        REFERENCES crypto_providers (id) ON DELETE RESTRICT ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed default SoftHSM2 driver (PKCS11J embedded JNI wrapper) + two local SoftHSM2 tokens
INSERT IGNORE INTO crypto_providers (code, name, wrapper_type, library_path, library_wrapper_path, enabled)
VALUES ('softhsm2', 'SoftHSM v2 (PKCS11J)', 'PKCS11J', '/usr/lib/softhsm/libsofthsm2.so', 'embedded', TRUE);

INSERT IGNORE INTO crypto_devices (device_id, provider_id, token_label, slot_id, slot_list_index, pool_size, prehash_in_jvm, is_default, enabled)
SELECT 'softhsm-primary', id, 'ocsp-signing', NULL, 0, 4, FALSE, TRUE, TRUE
FROM crypto_providers WHERE code = 'softhsm2';

INSERT IGNORE INTO crypto_devices (device_id, provider_id, token_label, slot_id, slot_list_index, pool_size, prehash_in_jvm, is_default, enabled)
SELECT 'softhsm-secondary', id, 'ocsp-signing-2', NULL, 1, 4, FALSE, FALSE, TRUE
FROM crypto_providers WHERE code = 'softhsm2';

