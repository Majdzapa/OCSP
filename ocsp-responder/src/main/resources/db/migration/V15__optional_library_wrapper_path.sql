-- =============================================================================
-- Incert OCSP Subsystem — Flyway Migration V15: Optional library_wrapper_path
-- Allows crypto_providers.library_wrapper_path to be NULL so org.xipki:ipkcs11wrapper
-- uses its built-in OS/arch native loader by default (no hardcoded Linux .so path).
-- =============================================================================

ALTER TABLE crypto_providers
    MODIFY COLUMN library_wrapper_path VARCHAR(500) NULL DEFAULT NULL;

UPDATE crypto_providers
SET library_wrapper_path = NULL
WHERE code = 'softhsm2'
  AND library_wrapper_path = '/opt/pkcs11j/libpkcs11wrapper.so';

