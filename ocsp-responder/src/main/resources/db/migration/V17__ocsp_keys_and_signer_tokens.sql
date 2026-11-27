-- =============================================================================
-- Incert OCSP Subsystem — Flyway Migration V17: Cryptographic Key Entity & Signer Tokens
-- 1. Creates `ocsp_keys` to persist key metadata + public key SPKI extracted once from
--    the PKCS#11 token (eliminating repetitive token object scans and NVRAM cert writes).
-- 2. Replaces `ocsp_signer_vslots` with `ocsp_signer_tokens` (ordered PRIMARY + FAILOVER tokens).
-- 3. Links `ocsp_signers.key_id` -> `ocsp_keys.id`.
-- =============================================================================

CREATE TABLE IF NOT EXISTS ocsp_keys (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    key_label        VARCHAR(150) NOT NULL,
    cka_id_hex       VARCHAR(300) NULL,
    token_device_id  BIGINT       NULL,
    key_algorithm    VARCHAR(32)  NOT NULL,
    key_size         INT          NOT NULL,
    public_key_pem   TEXT         NOT NULL,
    public_key_sha1  VARCHAR(64)  NOT NULL,
    generated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_ocsp_keys_label UNIQUE (key_label),
    CONSTRAINT fk_ocsp_keys_token_device FOREIGN KEY (token_device_id)
        REFERENCES crypto_devices (id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ocsp_signer_tokens (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    signer_id       BIGINT      NOT NULL,
    token_device_id BIGINT      NOT NULL,
    priority_order  INT         NOT NULL DEFAULT 0,
    role            VARCHAR(32) NOT NULL DEFAULT 'PRIMARY',
    CONSTRAINT uq_ocsp_signer_tokens UNIQUE (signer_id, token_device_id),
    CONSTRAINT fk_ocsp_signer_tokens_signer FOREIGN KEY (signer_id)
        REFERENCES ocsp_signers (id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_ocsp_signer_tokens_device FOREIGN KEY (token_device_id)
        REFERENCES crypto_devices (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Migrate any existing rows from ocsp_signer_vslots into ocsp_signer_tokens, then drop ocsp_signer_vslots
INSERT IGNORE INTO ocsp_signer_tokens (id, signer_id, token_device_id, priority_order, role)
SELECT id, signer_id, device_id, priority_order, role
FROM ocsp_signer_vslots;

DROP TABLE IF EXISTS ocsp_signer_vslots;

ALTER TABLE ocsp_signers
    ADD COLUMN IF NOT EXISTS key_id BIGINT NULL AFTER subject_dn,
    ADD CONSTRAINT fk_ocsp_signers_key FOREIGN KEY (key_id)
        REFERENCES ocsp_keys (id) ON DELETE SET NULL ON UPDATE CASCADE;

