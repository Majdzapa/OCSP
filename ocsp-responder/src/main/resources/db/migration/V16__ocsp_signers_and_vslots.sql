-- =============================================================================
-- Incert OCSP Subsystem — Flyway Migration V16: First-Class OCSP Signer Aggregate
-- Unifies Signer identity, crypto policy (key + signing algorithm), ordered HSM
-- Vslots (1..N crypto_devices for HA failover), generated PKCS#10 CSR, and
-- imported X.509 certificate.
-- =============================================================================

CREATE TABLE IF NOT EXISTS ocsp_signers (
    id                     BIGINT AUTO_INCREMENT PRIMARY KEY,
    code                   VARCHAR(100) NOT NULL,
    name                   VARCHAR(150) NOT NULL,
    status                 VARCHAR(32)  NOT NULL DEFAULT 'DRAFT',
    subject_dn             VARCHAR(500) NOT NULL,
    key_label              VARCHAR(150) NOT NULL,
    key_algorithm          VARCHAR(32)  NOT NULL DEFAULT 'RSA',
    key_size               INT          NOT NULL DEFAULT 3072,
    signature_algorithm    VARCHAR(64)  NOT NULL DEFAULT 'SHA256withRSA',
    csr_pem                TEXT         NULL,
    csr_generated_at       DATETIME(6)  NULL,
    certificate_pem        TEXT         NULL,
    cert_subject_dn        VARCHAR(500) NULL,
    cert_issuer_dn         VARCHAR(500) NULL,
    cert_serial_number     VARCHAR(128) NULL,
    cert_not_before        DATETIME(6)  NULL,
    cert_not_after         DATETIME(6)  NULL,
    signing_certificate_id BIGINT       NULL,
    active                 BOOLEAN      NOT NULL DEFAULT FALSE,
    activated_at           DATETIME(6)  NULL,
    created_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_ocsp_signers_code UNIQUE (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ocsp_signer_vslots (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    signer_id      BIGINT      NOT NULL,
    device_id      BIGINT      NOT NULL,
    priority_order INT         NOT NULL DEFAULT 0,
    role           VARCHAR(32) NOT NULL DEFAULT 'PRIMARY',
    CONSTRAINT uq_ocsp_signer_vslots UNIQUE (signer_id, device_id),
    CONSTRAINT fk_ocsp_signer_vslots_signer FOREIGN KEY (signer_id)
        REFERENCES ocsp_signers (id) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_ocsp_signer_vslots_device FOREIGN KEY (device_id)
        REFERENCES crypto_devices (id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

