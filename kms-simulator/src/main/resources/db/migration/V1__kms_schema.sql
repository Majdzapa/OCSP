-- V1__kms_schema.sql
-- KMS Simulator schema
-- certificate, outbox_event, job_run tables

CREATE TABLE certificate (
    id                   BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    serial_number_hex    VARCHAR(128)    NOT NULL,
    issuer_dn            VARCHAR(512)    NOT NULL,
    issuer_key_hash_hex  VARCHAR(40)     NOT NULL COMMENT 'Hex SHA-1 of issuer public key',
    issuer_name_hash_hex VARCHAR(40)     NOT NULL COMMENT 'Hex SHA-1 of issuer DN',
    subject_dn           VARCHAR(512)    NOT NULL,
    not_before           DATETIME(3)     NOT NULL,
    not_after            DATETIME(3)     NOT NULL,
    status               ENUM('GOOD','REVOKED') NOT NULL DEFAULT 'GOOD',
    revocation_time      DATETIME(3)     NULL,
    revocation_reason    VARCHAR(30)     NULL COMMENT 'RFC 5280 CRLReason name',
    pem_encoded          MEDIUMTEXT      NULL,
    sequence             BIGINT          NOT NULL DEFAULT 0 COMMENT 'Monotonic per-certificate counter',
    updated_at           DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
                                          ON UPDATE CURRENT_TIMESTAMP(3),

    UNIQUE KEY uq_serial (serial_number_hex),
    INDEX idx_status     (status),
    INDEX idx_issuer_key (issuer_key_hash_hex)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Certificate inventory managed by the KMS simulator';


CREATE TABLE outbox_event (
    event_id   VARCHAR(64)  NOT NULL PRIMARY KEY,
    topic      VARCHAR(128) NOT NULL,
    kafka_key  VARCHAR(256) NOT NULL,
    payload    TEXT         NOT NULL,
    created_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    sent_at    DATETIME(3)  NULL,
    sent       BOOLEAN      NOT NULL DEFAULT FALSE,

    INDEX idx_pending (sent, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Transactional outbox for Kafka events';


CREATE TABLE job_run (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    job_name        VARCHAR(64)  NOT NULL,
    started_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    finished_at     DATETIME(3)  NULL,
    certs_revoked   INT          NOT NULL DEFAULT 0,
    certs_unrevoked INT          NOT NULL DEFAULT 0,
    status          ENUM('RUNNING','SUCCESS','FAILED') NOT NULL DEFAULT 'RUNNING',
    error_message   TEXT         NULL,

    INDEX idx_job_name (job_name),
    INDEX idx_started  (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Audit log for KMS revocation job runs';
