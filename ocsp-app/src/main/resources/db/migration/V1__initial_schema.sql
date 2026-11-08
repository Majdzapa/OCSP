-- V1__initial_schema.sql
-- OCSP subsystem MariaDB schema — initial version
-- All tables use InnoDB for ACID guarantees and row-level locking.
-- Schema version managed by Flyway.

-- ============================================================
-- revocation_status
-- Source of truth for OCSP certificate status.
-- Written exclusively by ocsp-sync-service; read-only for ocsp-responder.
-- ============================================================
CREATE TABLE revocation_status (
    id                  BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    issuer_name_hash    BINARY(20)      NOT NULL COMMENT 'SHA-1 of issuer DN (RFC 6960 CertID)',
    issuer_key_hash     BINARY(20)      NOT NULL COMMENT 'SHA-1 of issuer public key (RFC 6960 CertID)',
    serial_number       VARBINARY(64)   NOT NULL COMMENT 'Certificate serial number bytes',
    status              ENUM('GOOD','REVOKED','UNKNOWN') NOT NULL DEFAULT 'GOOD',
    revocation_time     DATETIME(3)     NULL     COMMENT 'Time revocation took effect; NULL when GOOD',
    revocation_reason   VARCHAR(40)     NULL     COMMENT 'RFC 5280 reason string, e.g. keyCompromise',
    this_update         DATETIME(3)     NOT NULL COMMENT 'thisUpdate field for OCSP responses',
    updated_at          DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
                                         ON UPDATE CURRENT_TIMESTAMP(3),
    source_event_id     VARCHAR(64)     NOT NULL COMMENT 'Idempotency key from KMS domain event',

    UNIQUE KEY uq_cert_id       (issuer_name_hash, issuer_key_hash, serial_number),
    UNIQUE KEY uq_source_event  (source_event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='OCSP certificate revocation status, replicated from KMS events';


-- ============================================================
-- ocsp_response_cache
-- Shared L2 cache of pre-signed OCSP responses.
-- Purged by a scheduled job once next_update has elapsed.
-- ============================================================
CREATE TABLE ocsp_response_cache (
    cache_key           CHAR(40)        NOT NULL PRIMARY KEY
                                         COMMENT 'SHA-1 hex of CertID (issuerNameHash||issuerKeyHash||serial)',
    der_response        MEDIUMBLOB      NOT NULL COMMENT 'DER-encoded OCSPResponse bytes',
    this_update         DATETIME(3)     NOT NULL,
    next_update         DATETIME(3)     NOT NULL,
    created_at          DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX idx_next_update (next_update)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Shared L2 cache of pre-signed OCSP responses';


-- ============================================================
-- cert_event_audit
-- Audit trail for every KMS domain event received by the sync service.
-- ============================================================
CREATE TABLE cert_event_audit (
    event_id            VARCHAR(64)     NOT NULL PRIMARY KEY COMMENT 'KMS event UUID (idempotency key)',
    event_type          VARCHAR(40)     NOT NULL COMMENT 'CertificateIssued | CertificateRevoked | ...',
    serial_number       VARBINARY(64)   NOT NULL,
    received_at         DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    processed_at        DATETIME(3)     NULL,
    status              ENUM('RECEIVED','PROCESSED','FAILED') NOT NULL DEFAULT 'RECEIVED',
    error_message       TEXT            NULL,

    INDEX idx_received_at   (received_at),
    INDEX idx_status        (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Audit log of all KMS certificate events processed by the sync service';


-- ============================================================
-- ocsp_signing_cert
-- Tracks the lifecycle of delegated OCSP signing certificates issued by Incert.
-- ============================================================
CREATE TABLE ocsp_signing_cert (
    id                  BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    serial_number       VARBINARY(64)   NOT NULL,
    not_before          DATETIME(3)     NOT NULL,
    not_after           DATETIME(3)     NOT NULL,
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE,
    kms_key_reference   VARCHAR(128)    NOT NULL COMMENT 'Opaque KMS key handle — never raw key material',
    created_at          DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX idx_not_after     (not_after),
    INDEX idx_is_active     (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Delegated OCSP signing certificate lifecycle tracking';
