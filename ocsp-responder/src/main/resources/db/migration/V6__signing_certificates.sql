-- =============================================================================
-- Incert OCSP Subsystem — Flyway Migration V6: Signing Certificates Registry
-- Supports dynamic signing certificate management with exactly one active signer
-- =============================================================================

CREATE TABLE IF NOT EXISTS signing_certificates (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    alias VARCHAR(100) NOT NULL UNIQUE,
    key_label VARCHAR(100) NOT NULL,
    certificate_pem MEDIUMTEXT NOT NULL,
    subject_dn VARCHAR(500) NOT NULL,
    issuer_dn VARCHAR(500) NOT NULL,
    serial_number VARCHAR(100) NOT NULL,
    not_before TIMESTAMP NULL,
    not_after TIMESTAMP NULL,
    signature_algorithm VARCHAR(50) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    activated_at TIMESTAMP NULL,
    INDEX idx_sign_cert_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

