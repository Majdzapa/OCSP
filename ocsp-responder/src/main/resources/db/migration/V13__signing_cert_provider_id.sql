-- =============================================================================
-- Incert OCSP Subsystem — Flyway Migration V13: Multi-Device Provider ID
-- Associates each registered OCSP signing certificate with a specific HSM
-- provider / device ID managed by PkcsProviders (e.g. softhsm-primary,
-- softhsm-secondary, thales-luna, etc.).
-- =============================================================================

ALTER TABLE signing_certificates
    ADD COLUMN provider_id VARCHAR(100) NOT NULL DEFAULT 'default' AFTER alias;

