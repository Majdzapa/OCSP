-- V2__db_users.sql
-- Create application-level MariaDB users with least-privilege access.
-- Run by a DBA/operator (not by Flyway in production — adjust as needed).

-- Read-only user for ocsp-responder
CREATE USER IF NOT EXISTS 'ocsp_reader'@'%' IDENTIFIED BY 'changeme_in_production';
GRANT SELECT ON ocsp.revocation_status     TO 'ocsp_reader'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON ocsp.ocsp_response_cache TO 'ocsp_reader'@'%';

-- Read-write user for ocsp-sync-service
CREATE USER IF NOT EXISTS 'ocsp_writer'@'%' IDENTIFIED BY 'changeme_in_production';
GRANT SELECT, INSERT, UPDATE ON ocsp.revocation_status TO 'ocsp_writer'@'%';
GRANT SELECT, INSERT, UPDATE ON ocsp.cert_event_audit  TO 'ocsp_writer'@'%';

-- Admin user for ocsp-admin-api (read-only on data tables, write on cache invalidation)
CREATE USER IF NOT EXISTS 'ocsp_admin'@'%' IDENTIFIED BY 'changeme_in_production';
GRANT SELECT ON ocsp.revocation_status     TO 'ocsp_admin'@'%';
GRANT SELECT ON ocsp.cert_event_audit      TO 'ocsp_admin'@'%';
GRANT SELECT ON ocsp.ocsp_signing_cert     TO 'ocsp_admin'@'%';
GRANT SELECT, DELETE ON ocsp.ocsp_response_cache TO 'ocsp_admin'@'%';

FLUSH PRIVILEGES;
