-- V5__inbox_event.sql
-- Transactional Inbox recording all certificate status change events received via RabbitMQ

CREATE TABLE IF NOT EXISTS inbox_event (
    event_id            VARCHAR(64)     NOT NULL PRIMARY KEY COMMENT 'KMS event UUID / outbox ID',
    event_type          VARCHAR(64)     NOT NULL DEFAULT 'CERTIFICATE_STATUS_CHANGED',
    certificate_serial  VARCHAR(128)    NOT NULL COMMENT 'Certificate serial hex',
    status              VARCHAR(32)     NOT NULL COMMENT 'GOOD, REVOKED',
    revocation_reason   VARCHAR(64)     NULL,
    revocation_time     DATETIME(3)     NULL,
    sequence            BIGINT          NOT NULL DEFAULT 0,
    payload             TEXT            NULL,
    received_at         DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    processed_at        DATETIME(3)     NULL,
    processing_status   VARCHAR(32)     NOT NULL DEFAULT 'RECEIVED' COMMENT 'RECEIVED, PROCESSED, DUPLICATE, SKIPPED, FAILED',
    error_message       TEXT            NULL,

    INDEX idx_inbox_serial (certificate_serial),
    INDEX idx_inbox_received (received_at),
    INDEX idx_inbox_status (processing_status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Transactional inbox recording every certificate event received by responder';

