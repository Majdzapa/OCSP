-- V3__kafka_sync.sql
-- OCSP subsystem MariaDB schema — Kafka sync & SoftHSM re-architecture
-- Schema version managed by Flyway.

-- 1. Add sequence column to revocation_status for out-of-order protection
ALTER TABLE revocation_status
    ADD COLUMN IF NOT EXISTS sequence BIGINT NOT NULL DEFAULT 0
    COMMENT 'Monotonic per-certificate sequence counter from KMS';

-- 2. Update ocsp_signing_cert to track HSM key label instead of KMS key reference
ALTER TABLE ocsp_signing_cert
    ADD COLUMN IF NOT EXISTS hsm_key_label VARCHAR(128) NOT NULL DEFAULT 'ocsp-signing-key'
    COMMENT 'PKCS#11 HSM token key label';

-- 3. Add consumed Kafka offsets tracking table for audit & ops
CREATE TABLE IF NOT EXISTS kafka_consumer_offset (
    topic_partition VARCHAR(128) NOT NULL PRIMARY KEY COMMENT 'topic:partition',
    committed_offset BIGINT      NOT NULL,
    updated_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
                                   ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Audit log of Kafka consumer committed offsets';

-- 4. Create kms database and application user for the new topology
CREATE DATABASE IF NOT EXISTS kms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'kms_app'@'%' IDENTIFIED BY 'changeme';
GRANT ALL PRIVILEGES ON kms.* TO 'kms_app'@'%';

CREATE USER IF NOT EXISTS 'ocsp_app'@'%' IDENTIFIED BY 'changeme';
GRANT ALL PRIVILEGES ON ocsp.* TO 'ocsp_app'@'%';

-- 5. Spring Modulith event publication table
CREATE TABLE IF NOT EXISTS event_publication (
    id UUID NOT NULL,
    listener_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(255) NOT NULL,
    serialized_event VARCHAR(255) NOT NULL,
    publication_date DATETIME(6) NOT NULL,
    completion_date DATETIME(6) DEFAULT NULL,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

FLUSH PRIVILEGES;
