-- =============================================================================
-- Incert OCSP Subsystem — Flyway Migration V18: Multi-Key Signer Rollover (EJBCA Pattern)
-- Allows each OCSP Signer (ocsp_signers) to own 1..N cryptographic keys in ocsp_keys
-- (each with its own CSR, CA-signed X.509 certificate, and active flag) while enforcing
-- at most ONE active key per Signer and per HSM Token for zero-downtime key rotation.
-- =============================================================================

ALTER TABLE ocsp_keys
    ADD COLUMN IF NOT EXISTS signer_id              BIGINT       NULL AFTER token_device_id,
    ADD COLUMN IF NOT EXISTS csr_pem                TEXT         NULL AFTER public_key_sha1,
    ADD COLUMN IF NOT EXISTS csr_generated_at       DATETIME(6)  NULL AFTER csr_pem,
    ADD COLUMN IF NOT EXISTS certificate_pem        TEXT         NULL AFTER csr_generated_at,
    ADD COLUMN IF NOT EXISTS cert_subject_dn        VARCHAR(500) NULL AFTER certificate_pem,
    ADD COLUMN IF NOT EXISTS cert_issuer_dn         VARCHAR(500) NULL AFTER cert_subject_dn,
    ADD COLUMN IF NOT EXISTS cert_serial_number     VARCHAR(128) NULL AFTER cert_issuer_dn,
    ADD COLUMN IF NOT EXISTS cert_not_before        DATETIME(6)  NULL AFTER cert_serial_number,
    ADD COLUMN IF NOT EXISTS cert_not_after         DATETIME(6)  NULL AFTER cert_not_before,
    ADD COLUMN IF NOT EXISTS signing_certificate_id BIGINT       NULL AFTER cert_not_after,
    ADD COLUMN IF NOT EXISTS active                 BOOLEAN      NOT NULL DEFAULT FALSE AFTER signing_certificate_id,
    ADD COLUMN IF NOT EXISTS activated_at           DATETIME(6)  NULL AFTER active;

-- Backfill existing keys linked from ocsp_signers.key_id
UPDATE ocsp_keys k
INNER JOIN ocsp_signers s ON s.key_id = k.id
SET k.signer_id              = s.id,
    k.csr_pem                = COALESCE(k.csr_pem, s.csr_pem),
    k.csr_generated_at       = COALESCE(k.csr_generated_at, s.csr_generated_at),
    k.certificate_pem        = COALESCE(k.certificate_pem, s.certificate_pem),
    k.cert_subject_dn        = COALESCE(k.cert_subject_dn, s.cert_subject_dn),
    k.cert_issuer_dn         = COALESCE(k.cert_issuer_dn, s.cert_issuer_dn),
    k.cert_serial_number     = COALESCE(k.cert_serial_number, s.cert_serial_number),
    k.cert_not_before        = COALESCE(k.cert_not_before, s.cert_not_before),
    k.cert_not_after         = COALESCE(k.cert_not_after, s.cert_not_after),
    k.signing_certificate_id = COALESCE(k.signing_certificate_id, s.signing_certificate_id),
    k.active                 = s.active,
    k.activated_at           = s.activated_at
WHERE k.signer_id IS NULL;

ALTER TABLE ocsp_keys
    ADD CONSTRAINT fk_ocsp_keys_signer FOREIGN KEY (signer_id)
        REFERENCES ocsp_signers (id) ON DELETE SET NULL ON UPDATE CASCADE;

