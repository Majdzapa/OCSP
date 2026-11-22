-- Optional mTLS / X.509 User Certificate assignment table
-- 1-way TLS does not require user certificates; when security.tls.client-cert-auth-enabled=true,
-- presented client certificates are matched by SHA-256 fingerprint to the linked user.

CREATE TABLE IF NOT EXISTS user_certificates (
    id                  CHAR(36)     NOT NULL PRIMARY KEY,
    user_id             CHAR(36)     NOT NULL,
    serial_number_hex   VARCHAR(128) NOT NULL,
    fingerprint_sha256  VARCHAR(64)  NOT NULL,
    subject_dn          VARCHAR(512) NOT NULL,
    issuer_dn           VARCHAR(512) NOT NULL,
    certificate_pem     TEXT         NOT NULL,
    not_before          TIMESTAMP    NULL,
    not_after           TIMESTAMP    NULL,
    revoked             BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_user_cert_fingerprint UNIQUE (fingerprint_sha256),
    CONSTRAINT fk_user_cert_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_user_cert_user_id ON user_certificates (user_id);
CREATE INDEX idx_user_cert_serial ON user_certificates (serial_number_hex);

