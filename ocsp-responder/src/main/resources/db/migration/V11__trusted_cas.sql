-- Trusted CA certificates for mTLS client-certificate verification (hot-reloaded in memory without restart)

CREATE TABLE IF NOT EXISTS trusted_cas (
    id                  CHAR(36)     NOT NULL PRIMARY KEY,
    alias               VARCHAR(128) NOT NULL,
    subject_dn          VARCHAR(512) NOT NULL,
    issuer_dn           VARCHAR(512) NOT NULL,
    serial_number_hex   VARCHAR(128) NOT NULL,
    fingerprint_sha256  VARCHAR(64)  NOT NULL,
    certificate_pem     TEXT         NOT NULL,
    not_before          TIMESTAMP    NULL,
    not_after           TIMESTAMP    NULL,
    enabled             BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_trusted_ca_alias UNIQUE (alias),
    CONSTRAINT uk_trusted_ca_fingerprint UNIQUE (fingerprint_sha256)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

