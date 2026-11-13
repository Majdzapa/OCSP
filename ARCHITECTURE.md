# Incert OCSP Subsystem — Architecture & Blueprint (v3.0)

> **Version**: 3.0 · **Architecture**: Layered Monolith · **Stack**: Java 21 · Spring Boot 3.3 · RabbitMQ 3.13 · SoftHSM2 (PKCS#11) · MariaDB 10.11 · Mantine UI v7 (React 18)

---

## Table of Contents
1. [Target System Blueprint](#1-target-system-blueprint)
2. [Sequence: OCSP Request Processing & PKCS#11 Dynamic Signing](#2-sequence-ocsp-request-processing--pkcs11-dynamic-signing)
3. [Sequence: Certificate Revocation via Transactional Outbox & RabbitMQ](#3-sequence-certificate-revocation-via-transactional-outbox--rabbitmq)
4. [OCSP Client & Relying Party Verification Flow](#4-ocsp-client--relying-party-verification-flow)
5. [Database Data Models (ERDs)](#5-database-data-models-erds)
6. [RabbitMQ Messaging Topology](#6-rabbitmq-messaging-topology)
7. [Deployment Blueprint](#7-deployment-blueprint)
8. [Security & Cryptographic Boundary Diagram](#8-security--cryptographic-boundary-diagram)

---

## 1. Target System Blueprint

```mermaid
graph TB
    subgraph EXTERNAL["External Relying Parties & Operators"]
        RP["🌐 Relying Parties<br/>(TLS Clients, Browsers, mTLS Gateways)"]
        CLIENT_USER["💻 Client Apps<br/>/api/v1/client/check"]
        OPS["👤 Security Operators<br/>Mantine Web Console :3000"]
    end

    subgraph KMS_ZONE["KMS Simulator Zone (:8090)"]
        KMS["kms-simulator<br/>────────────────<br/>• Certificate Inventory<br/>• Test PKI Seeder<br/>• Scheduled Revocation Job<br/>• Transactional Outbox Relay"]
        KMS_DB[("MariaDB<br/>schema: kms<br/>• certificate<br/>• outbox_event<br/>• job_run")]
        KMS --> KMS_DB
    end

    subgraph BROKER["Message Broker (RabbitMQ :5672 / :15672)"]
        EXCHANGE["Direct Exchange: incert.certificate.status<br/>Routing Key: incert.certificate.status.v1"]
        QUEUE["Durable Queue: ocsp.certificate.status"]
        DLX["DLX: incert.certificate.status.dlx"]
        DLQ["DLQ: ocsp.certificate.status.dlq"]
        EXCHANGE --> QUEUE
        QUEUE -.->|Dead-Letter| DLX --> DLQ
    end

    subgraph OCSP_MONOLITH["OCSP Monolith Application (ocsp-app :8080)"]
        subgraph CONTROLLERS["Layered Controllers"]
            RESP_CTRL["OcspResponderController<br/>POST /ocsp<br/>GET /ocsp/{base64url}"]
            CLIENT_CTRL["OcspClientController<br/>POST /api/v1/client/check"]
            ADMIN_CTRL["Admin / Feed / CertCheck Controllers<br/>/api/v1/admin/**"]
        end

        subgraph SERVICES["Business Services"]
            RESP_SVC["OcspResponderService<br/>RFC 6960 parsing & response assembly"]
            CLIENT_SVC["OcspClientService<br/>OCSP Client validator & verifier"]
            STATUS_SVC["CertificateStatusService<br/>Direct DB lookups & sequence validation"]
            LISTENER["CertificateStatusListener<br/>@RabbitListener consumer"]
            RECON_SVC["ReconciliationService<br/>Startup sync from KMS snapshot"]
        end

        subgraph HSM_ZONE["SoftHSM2 Token (PKCS#11) 🔒"]
            TOKEN["SoftHSM2 Token: ocsp-signing<br/>• Delegated Signing Key (RSA 3072)<br/>• Non-extractable Private Key<br/>• Delegated OCSP Certificate"]
        end

        RESP_CTRL --> RESP_SVC
        CLIENT_CTRL --> CLIENT_SVC
        ADMIN_CTRL --> STATUS_SVC
        ADMIN_CTRL --> RESP_SVC

        RESP_SVC --> STATUS_SVC
        RESP_SVC --> TOKEN
        CLIENT_SVC --> RESP_CTRL
        LISTENER --> STATUS_SVC
        RECON_SVC --> STATUS_SVC
    end

    subgraph DB["OCSP Data Layer (:3307)"]
        OCSP_DB[("MariaDB<br/>schema: ocsp<br/>• revocation_status<br/>• ocsp_signing_cert")]
        STATUS_SVC --> OCSP_DB
    end

    subgraph CONSOLE["Frontend Web Console (:3000)"]
        REACT["Mantine UI v7 Console<br/>React 18 · Vite · Tabler Icons<br/>Dashboard, KMS Manager, Feed, Cert Checker"]
    end

    RP --> RESP_CTRL
    CLIENT_USER --> CLIENT_CTRL
    OPS --> REACT
    REACT --> OCSP_MONOLITH
    REACT --> KMS
    KMS -- "Transactional Outbox Relay" --> EXCHANGE
    QUEUE --> LISTENER
```

---

## 2. Sequence: OCSP Request Processing & PKCS#11 Dynamic Signing

Every OCSP request (whether containing a nonce or nonce-free) queries the MariaDB `revocation_status` table directly and is dynamically signed by SoftHSM2 via PKCS#11. No caching layer is present, ensuring real-time revocation consistency and zero stale responses.

```mermaid
sequenceDiagram
    autonumber
    actor Client as Relying Party (OpenSSL / TLS Client)
    participant Ctrl as OcspResponderController
    participant Svc as OcspResponderService
    participant DB_Svc as CertificateStatusService
    participant DB as MariaDB (revocation_status)
    participant Signer as Pkcs11OcspSigner
    participant HSM as SoftHSM2 (/usr/lib/softhsm/libsofthsm2.so)

    Client->>Ctrl: POST /ocsp (DER application/ocsp-request)
    Ctrl->>Svc: processOcspRequest(derBytes)
    Svc->>Svc: Parse OCSPReq (RFC 6960), extract CertID & Nonce
    Svc->>DB_Svc: getStatus(issuerKeyHash, serialNumber)
    DB_Svc->>DB: SELECT * FROM revocation_status WHERE serial_number_hex=?
    DB-->>DB_Svc: Return CertificateStatus (GOOD, REVOKED, or UNKNOWN)
    DB_Svc-->>Svc: CertificateStatusResult

    Svc->>Svc: Build BasicOCSPResponse (thisUpdate=now, nextUpdate=now+24h)
    opt Nonce present in request
        Svc->>Svc: Echo Nonce extension into SingleResponse (RFC 6960 §4.4.1)
    end

    Svc->>Signer: sign(basicOcspRespBuilder)
    Signer->>HSM: C_SignInit(CKM_SHA256_RSA_PKCS) + C_Sign()
    HSM-->>Signer: Digital Signature Bytes
    Signer-->>Svc: Signed BasicOCSPResp
    Svc->>Svc: Wrap in OCSPResp (SUCCESSFUL)
    Svc-->>Ctrl: byte[] (DER OCSPResp)
    Ctrl-->>Client: 200 OK (Content-Type: application/ocsp-response)
```

---

## 3. Sequence: Certificate Revocation via Transactional Outbox & RabbitMQ

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Operator / Scheduled Job
    participant KMS as kms-simulator
    participant KMS_DB as MariaDB (schema: kms)
    participant Relay as RabbitMqOutboxRelayAdapter
    participant Rabbit as RabbitMQ (Exchange: incert.certificate.status)
    participant Listener as CertificateStatusListener (ocsp-app)
    participant Svc as CertificateStatusService
    participant OCSP_DB as MariaDB (schema: ocsp)

    Admin->>KMS: POST /kms/certificates/{serial}/revoke (reason)
    critical Atomic DB Transaction
        KMS->>KMS_DB: UPDATE certificate SET status='REVOKED', sequence=sequence+1
        KMS->>KMS_DB: INSERT INTO outbox_event (event_type, payload, sent=0)
    end
    KMS-->>Admin: 200 OK (Certificate Revoked)

    loop Every 500ms
        Relay->>KMS_DB: SELECT * FROM outbox_event WHERE sent=0 LIMIT 50
        KMS_DB-->>Relay: Outbox records
        Relay->>Rabbit: amqpTemplate.convertAndSend(exchange, routingKey, jsonPayload)
        Rabbit-->>Relay: Broker ACK
        Relay->>KMS_DB: UPDATE outbox_event SET sent=1 WHERE id=?
    end

    Rabbit->>Listener: Deliver to queue 'ocsp.certificate.status'
    Listener->>Svc: applyStatusEvent(CertificateStatusEvent)
    Svc->>OCSP_DB: SELECT sequence FROM revocation_status WHERE serial=?
    opt In-order sequence (event.sequence > db.sequence)
        Svc->>OCSP_DB: INSERT/UPDATE revocation_status (status, reason, sequence)
    end
    Listener->>Rabbit: Auto-ACK (or Reject/Dead-Letter to DLQ on poison message)
```

---

## 4. OCSP Client & Relying Party Verification Flow

The monolith includes a built-in RFC 6960 OCSP Client service (`OcspClientService`) accessible via `POST /api/v1/client/check`:

1. **Request Construction**: Builds an RFC 6960 `OCSPReq` using Bouncy Castle, creating the target `CertID` (SHA-1 over Issuer Name and Public Key). Generates an optional cryptographically secure random nonce.
2. **HTTP Dispatch**: Transports the DER request via HTTP `POST` or `GET` (base64url) to the OCSP responder endpoint.
3. **Response Parsing & Status Validation**: Decodes the `OCSPResp` and validates `responseStatus == SUCCESSFUL`.
4. **Signature Verification**: Verifies the RSA-SHA256 signature against the responder's public key certificate.
5. **Delegated Signer Authorization**: Enforces RFC 6960 §4.2.2.2 (responder cert must contain `id-kp-OCSPSigning` Extended Key Usage and be issued by the target CA).
6. **Freshness & Nonce Matching**: Ensures `thisUpdate <= now <= nextUpdate` and verifies that the echoed nonce matches the transmitted nonce.

---

## 5. Database Data Models (ERDs)

```mermaid
erDiagram
    %% KMS Schema
    KMS_CERTIFICATE {
        VARCHAR(64) serial_number_hex PK
        VARCHAR(256) subject_dn
        VARCHAR(256) issuer_dn
        VARCHAR(64) issuer_key_hash_hex
        VARCHAR(64) issuer_name_hash_hex
        DATETIME not_before
        DATETIME not_after
        VARCHAR(16) status
        VARCHAR(32) revocation_reason
        DATETIME revocation_time
        BIGINT sequence
        TEXT pem_encoded
    }

    KMS_OUTBOX_EVENT {
        VARCHAR(36) id PK
        VARCHAR(64) event_type
        VARCHAR(256) kafka_key
        LONGTEXT payload
        DATETIME created_at
        TINYINT sent
    }

    %% OCSP Subsystem Schema
    OCSP_REVOCATION_STATUS {
        VARCHAR(64) serial_number_hex PK
        VARCHAR(64) issuer_key_hash_hex
        VARCHAR(16) status
        VARCHAR(32) revocation_reason
        DATETIME revocation_time
        BIGINT sequence
        DATETIME this_update
        DATETIME next_update
        DATETIME updated_at
    }

    OCSP_SIGNING_CERT {
        VARCHAR(64) serial_number_hex PK
        VARCHAR(256) key_reference
        DATETIME not_before
        DATETIME not_after
        TINYINT active
        TEXT pem_encoded
    }
```

---

## 6. RabbitMQ Messaging Topology

| Component | Identifier | Details |
|---|---|---|
| **Direct Exchange** | `incert.certificate.status` | Durable direct exchange for PKI events |
| **Routing Key** | `incert.certificate.status.v1` | Routing key for status update events |
| **Durable Queue** | `ocsp.certificate.status` | Consumer queue with DLX bound |
| **Dead-Letter Exchange (DLX)** | `incert.certificate.status.dlx` | Direct exchange for rejected/poison messages |
| **Dead-Letter Queue (DLQ)** | `ocsp.certificate.status.dlq` | Durable queue capturing failed consumer deliveries |

---

## 7. Deployment Blueprint

```mermaid
graph LR
    subgraph DOCKER_COMPOSE["Docker Compose Environment"]
        MARIADB["ocsp-mariadb<br/>mariadb:10.11<br/>Port 3307"]
        RABBIT["ocsp-rabbitmq<br/>rabbitmq:3.13-management<br/>Ports 5672, 15672"]
        KMS_SVC["ocsp-kms<br/>kms-simulator:local<br/>Port 8090"]
        APP_SVC["ocsp-app<br/>ocsp/app:local<br/>Port 8080"]
        WEB_SVC["ocsp-console<br/>ocsp/console:local<br/>Port 3000"]
    end

    APP_SVC --> MARIADB
    APP_SVC --> RABBIT
    KMS_SVC --> MARIADB
    KMS_SVC --> RABBIT
    APP_SVC --> KMS_SVC
    WEB_SVC --> APP_SVC
    WEB_SVC --> KMS_SVC
```

---

## 8. Security & Cryptographic Boundary Diagram

```mermaid
graph TD
    subgraph CONTAINER["ocsp-app Container Sandbox Boundary"]
        subgraph PROCESS["JVM (Java 21)"]
            APP_CODE["Monolith Code (Responder + Client + Admin)"]
            SUN_PKCS11["SunPKCS11 Provider<br/>sun.security.pkcs11.SunPKCS11"]
        end

        subgraph SOFTHSM["SoftHSM2 Security Module"]
            LIB["libsofthsm2.so"]
            TOKEN_STORE["Encrypted Token Storage: /var/lib/softhsm/tokens"]
            PRIV_KEY["🔒 Delegated OCSP Private Key (RSA 3072)<br/>CKA_PRIVATE = TRUE<br/>CKA_SENSITIVE = TRUE<br/>CKA_EXTRACTABLE = FALSE"]
        end

        APP_CODE --> SUN_PKCS11
        SUN_PKCS11 --> LIB
        LIB --> TOKEN_STORE
        TOKEN_STORE --- PRIV_KEY
    end

    style PRIV_KEY fill:#ff4d4f,stroke:#fff,stroke-width:2px,color:#fff
    style TOKEN_STORE fill:#391085,stroke:#722ed1,stroke-width:1px,color:#fff
```

- **Non-Extractable Keys**: The OCSP signing private key is generated directly inside the SoftHSM2 token (`CKA_EXTRACTABLE = FALSE`). Private key material never exists in application memory or container filesystem.
- **Audit & Protection**: Any compromised certificate is revoked in KMS, persisted via Transactional Outbox, published to RabbitMQ, and updated in MariaDB within milliseconds.
