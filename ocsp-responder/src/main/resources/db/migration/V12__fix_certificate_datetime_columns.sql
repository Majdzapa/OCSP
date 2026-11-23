-- =============================================================================
-- Incert OCSP Subsystem — Flyway Migration V12: Fix Certificate Datetime Columns
-- MariaDB TIMESTAMP is limited to 1970-01-01..2038-01-19 (32-bit Unix epoch),
-- which causes "Incorrect datetime value" errors when importing Root CAs or
-- certificates with validity dates beyond 2038 (e.g. 2051-11-18).
-- Convert certificate validity columns to DATETIME(3) (supports 1000..9999).
-- =============================================================================

ALTER TABLE trusted_cas
    MODIFY COLUMN not_before DATETIME(3) NULL,
    MODIFY COLUMN not_after  DATETIME(3) NULL;

ALTER TABLE user_certificates
    MODIFY COLUMN not_before DATETIME(3) NULL,
    MODIFY COLUMN not_after  DATETIME(3) NULL;

ALTER TABLE signing_certificates
    MODIFY COLUMN not_before DATETIME(3) NULL,
    MODIFY COLUMN not_after  DATETIME(3) NULL;
