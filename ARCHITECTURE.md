# Incert OCSP Subsystem — Architecture & Blueprint (v2.0)

> **Version**: 2.0 · **Stack**: Java 21 · Spring Boot 3.3 · Spring Modulith 1.2 · Apache Kafka 3.8 (KRaft) · SoftHSM2 (PKCS#11) · MariaDB 10.11 · React 18

---

## Table of Contents
1. [Target System Blueprint](#1-target-system-blueprint)
2. [Sequence: OCSP Request Processing & PKCS#11 Signing](#2-sequence-ocsp-request-processing--pkcs11-signing)
3. [Sequence: Certificate Revocation via Transactional Outbox & Kafka](#3-sequence-certificate-revocation-via-transactional-outbox--kafka)
4. [Sequence: In-Process Cache Invalidation](#4-sequence-in-process-cache-invalidation)
5. [Database Data Models (ERDs)](#5-database-data-models-erds)
6. [Kafka Topology](#6-kafka-topology)
7. [Deployment Blueprint](#7-deployment-blueprint)
8. [Security Boundary Diagram](#8-security-boundary-diagram)

---

## 1. Target System Blueprint

```mermaid
graph TB
    subgraph EXTERNAL["External Relying Parties"]
        RP["🌐 Relying Parties<br/>(TLS Clients, Browsers, mTLS Gateways)"]
        OPS["👤 Security Operators"]
    end

    subgraph KMS_ZONE["KMS Simulator Zone"]
        KMS["kms-simulator<br/>:8090<br/>────────────────<br/>• Certificate Inventory<br/>• Test PKI Seeder<br/>• Scheduled Revocation Job<br/>• Transactional Outbox Relay"]
        KMS_DB[("MariaDB<br/>schema: kms<br/>• certificate<br/>• outbox_event<br/>• job_run")]
        KMS --> KMS_DB
    end

    subgraph BROKER["Messaging Layer"]
        KAFKA["Apache Kafka (KRaft mode)<br/>────────────────<br/>Topic: incert.certificate.status.v1 (6 partitions)<br/>DLT: incert.certificate.status.v1.dlt<br/>Key: issuerKeyHash:serial"]
    end

    subgraph OCSP_APP["OCSP Application (Spring Modulith — ocsp-app :8080)"]
        subgraph MODULES["Internal Hexagonal Modules"]
            RESP["responder<br/>POST /ocsp<br/>GET /ocsp/{b64}"]
            STATUS["status<br/>Caffeine L1 Cache<br/>StatusLookup / StatusWriter"]
            SIGN["signing<br/>Pkcs11OcspSigner<br/>SunPKCS11 Provider"]
            SYNC["sync<br/>Kafka Consumer<br/>Idempotent Upsert"]
            ADMIN["admin<br/>/api/v1/admin/**<br/>Dashboard, Cache, Revocation Feed"]
        end

        subgraph HSM_ZONE["SoftHSM2 Token (PKCS#11) 🔒"]
            TOKEN["SoftHSM2 Token: ocsp-signing<br/>• Delegated Signing Key (RSA 3072)<br/>• Non-extractable Private Key<br/>• Delegated OCSP Certificate"]
        end

        RESP --> STATUS
        RESP --> SIGN
        SIGN --> TOKEN
        SYNC --> STATUS
        ADMIN --> STATUS
        ADMIN --> SIGN
    end

    subgraph DB["OCSP Data Layer"]
        OCSP_DB[("MariaDB<br/>schema: ocsp<br/>• revocation_status<br/>• ocsp_response_cache<br/>• ocsp_signing_cert<br/>• kafka_consumer_offset")]
    end

    subgraph UI["Management Console"]
        CONSOLE["ocsp-console<br/>:3000<br/>React 18 + Vite + Nginx Proxy"]
    end

    RP -- "RFC 6960 DER Request" --> RESP
    KMS -- "Transactional Outbox Events" --> KAFKA
    KAFKA -- "Consumer group: ocsp-sync" --> SYNC
    STATUS <--> OCSP_DB
    OPS --> CONSOLE
    CONSOLE -- "Reverse Proxy /api/v1/admin" --> ADMIN
    CONSOLE -- "Reverse Proxy /api/kms" --> KMS
```

---

## 2. Sequence: OCSP Request Processing & PKCS#11 Signing

```mermaid
sequenceDiagram
    autonumber
    participant RP as Relying Party (Client)
    participant RESP as OcspController (responder)
    participant SVC as OcspRequestHandlerService
    participant L1 as Caffeine Status Cache
    participant DB as MariaDB (revocation_status)
    participant HSM as SoftHSM2 (PKCS#11 SunPKCS11)

    RP->>RESP: POST /ocsp (DER OCSPRequest)
    RESP->>SVC: handle(derRequest)
    SVC->>SVC: Parse DER & extract CertID (issuer hashes + serial) + Nonce
    SVC->>L1: findStatus(certId)

    alt L1 Cache Hit
        L1-->>SVC: CertificateStatusRecord
    else L1 Cache Miss
        SVC->>DB: SELECT from revocation_status
        DB-->>SVC: CertificateStatusRecord
        SVC->>L1: Warm cache
    end

    SVC->>HSM: Sign BasicOCSPResp via SunPKCS11 (delegated key)
    Note over HSM: Private key never leaves SoftHSM token
    HSM-->>SVC: Cryptographic Signature
    SVC->>SVC: Assemble OCSPResponse + Nonce Echo
    SVC-->>RESP: DER OCSPResponse bytes
    RESP-->>RP: 200 OK (application/ocsp-response)
```

---

## 3. Sequence: Certificate Revocation via Transactional Outbox & Kafka

```mermaid
sequenceDiagram
    autonumber
    participant OP as Operator / Scheduled Job
    participant KMS as kms-simulator
    participant KDB as MariaDB (schema: kms)
    participant RELAY as KafkaOutboxRelayAdapter
    participant KAFKA as Kafka Topic (incert.certificate.status.v1)
    participant SYNC as CertificateStatusKafkaListener (ocsp-app)
    participant S_SVC as StatusChangeApplicationService
    participant O_DB as MariaDB (schema: ocsp)
    participant CACHE as Caffeine L1 Cache

    OP->>KMS: Revoke certificate (serial, reason)
    Note over KMS,KDB: Atomic DB Transaction:
    KMS->>KDB: UPDATE certificate SET status='REVOKED', sequence = sequence + 1
    KMS->>KDB: INSERT into outbox_event (eventId, key, payload, sent=false)
    KDB-->>KMS: Transaction Committed

    loop Every 500ms
        RELAY->>KDB: SELECT unsent events
        RELAY->>KAFKA: Publish with idempotent producer (acks=all)
        RELAY->>KDB: UPDATE outbox_event SET sent=true
    end

    KAFKA->>SYNC: Deliver message (key = issuerKeyHash:serial)
    SYNC->>S_SVC: apply(StatusChangeCommand)
    S_SVC->>O_DB: Idempotent upsert into revocation_status (sequence check)
    S_SVC->>CACHE: Direct In-Process Eviction: evict(certId)
    SYNC->>KAFKA: Manual Offset Commit
```

---

## 4. Sequence: In-Process Cache Invalidation

Because the OCSP responder and sync worker are merged into a single modular monolith (`ocsp-app`), cache invalidation no longer requires a message broker roundtrip. When a status update is committed by `sync`, the L1 Caffeine cache in `status` is evicted directly in-memory via the `CacheEvictor` port interface.

---

## 5. Database Data Models (ERDs)

### KMS Schema (`kms`)
```
+-----------------------------------------------------------+
|                        certificate                        |
+-----------------------------------------------------------+
| id                  BIGINT UNSIGNED PK AUTO_INCREMENT    |
| serial_number_hex   VARCHAR(128) UNIQUE                  |
| issuer_dn           VARCHAR(512)                          |
| issuer_key_hash_hex VARCHAR(40)                           |
| issuer_name_hash_hex VARCHAR(40)                          |
| subject_dn          VARCHAR(512)                          |
| not_before          DATETIME(3)                           |
| not_after           DATETIME(3)                           |
| status              ENUM('GOOD','REVOKED')                |
| revocation_time     DATETIME(3) NULL                      |
| revocation_reason   VARCHAR(30) NULL                      |
| pem_encoded         MEDIUMTEXT                            |
| sequence            BIGINT NOT NULL DEFAULT 0             |
| updated_at          DATETIME(3)                           |
+-----------------------------------------------------------+

+-----------------------------------------------------------+
|                       outbox_event                        |
+-----------------------------------------------------------+
| event_id            VARCHAR(64) PK                        |
| topic               VARCHAR(128)                          |
| kafka_key           VARCHAR(256)                          |
| payload             TEXT                                  |
| created_at          DATETIME(3)                           |
| sent_at             DATETIME(3) NULL                      |
| sent                BOOLEAN NOT NULL DEFAULT FALSE        |
+-----------------------------------------------------------+
```

### OCSP Schema (`ocsp`)
```
+-----------------------------------------------------------+
|                     revocation_status                     |
+-----------------------------------------------------------+
| id                  BIGINT UNSIGNED PK AUTO_INCREMENT    |
| issuer_name_hash    BINARY(20) NOT NULL                   |
| issuer_key_hash     BINARY(20) NOT NULL                   |
| serial_number       VARBINARY(64) NOT NULL                |
| status              ENUM('GOOD','REVOKED','UNKNOWN')      |
| revocation_time     DATETIME(3) NULL                      |
| revocation_reason   VARCHAR(30) NULL                      |
| this_update         DATETIME(3)                           |
| updated_at          DATETIME(3)                           |
| source_event_id     VARCHAR(64) UNIQUE                    |
| sequence            BIGINT NOT NULL DEFAULT 0             |
| UQ (issuer_name_hash, issuer_key_hash, serial_number)     |
+-----------------------------------------------------------+

+-----------------------------------------------------------+
|                    ocsp_signing_cert                      |
+-----------------------------------------------------------+
| id                  BIGINT UNSIGNED PK AUTO_INCREMENT    |
| serial_number       VARBINARY(64)                         |
| not_before          DATETIME(3)                           |
| not_after           DATETIME(3)                           |
| is_active           BOOLEAN NOT NULL DEFAULT TRUE         |
| hsm_key_label       VARCHAR(128)                          |
| created_at          DATETIME(3)                           |
+-----------------------------------------------------------+

+-----------------------------------------------------------+
|                   ocsp_response_cache (L2)                |
+-----------------------------------------------------------+
| cache_key           VARCHAR(128) PK (hex issuerKeyHash:sn)|
| der_response        LONGBLOB NOT NULL (pre-signed response|
| this_update         DATETIME(3)                           |
| next_update         DATETIME(3)                           |
| created_at          DATETIME(3)                           |
| INDEX idx_next_update (next_update)                       |
+-----------------------------------------------------------+
```

---

## 6. Kafka Topology

- **Topic**: `incert.certificate.status.v1`
  - Partitions: 6
  - Key: `issuerKeyHash:serialNumber` (guarantees strict per-certificate ordering)
  - Retention: 7 days
- **Dead Letter Topic**: `incert.certificate.status.v1.dlt`
  - Partitions: 1
  - Purpose: Poison message quarantine with header metadata

---

## 7. Deployment Blueprint

The target deployment operates 5 Docker containers:
1. `ocsp-mariadb`: Hosts databases `ocsp` and `kms` on port 3307/3306.
2. `ocsp-kafka`: Apache Kafka in KRaft mode (no ZooKeeper) on port 9092.
3. `ocsp-kms`: KMS simulator running seed PKI, REST management, and outbox relay on port 8090.
4. `ocsp-app`: Modulith containing responder, status cache, PKCS#11 signer, and sync consumer on port 8080.
5. `ocsp-console`: React 18 admin interface served via Nginx reverse proxy on port 3000.

---

## 8. Security Boundary Diagram

```mermaid
graph LR
    subgraph PUBLIC["Public Zone"]
        EP["/ocsp Endpoint<br/>Port 8080"]
    end

    subgraph APP["ocsp-app Container"]
        subgraph HSM["HSM Boundary 🔒"]
            KEY["SoftHSM2 Token<br/>RSA 3072 Key Pair<br/>CKA_EXTRACTABLE=false<br/>Private key NEVER leaves token"]
        end
        SIGN["Pkcs11OcspSigner<br/>SunPKCS11 Provider"]
        SIGN --> KEY
    end

    subgraph ADMIN_ZONE["Internal Admin Zone"]
        ADMIN_API["/api/v1/admin/**<br/>OAuth2 / OIDC Protected"]
    end

    EP --> SIGN
```
