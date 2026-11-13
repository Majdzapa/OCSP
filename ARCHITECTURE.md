# Incert OCSP Subsystem — Architecture & Blueprint (v4.0)

> **Version**: 4.0 · **Architecture**: Standalone Distributed Services & Pure Event Bus · **Stack**: Java 21 · Spring Boot 3.3 · RabbitMQ 3.13 · SoftHSM2 (PKCS#11) · MariaDB 10.11 · Mantine UI v7 (React 18)

---

## Table of Contents
1. [Target System Blueprint](#1-target-system-blueprint)
2. [Sequence: OCSP Request Processing & PKCS#11 Dynamic Signing](#2-sequence-ocsp-request-processing--pkcs11-dynamic-signing)
3. [Sequence: Certificate Revocation via Transactional Outbox & RabbitMQ](#3-sequence-certificate-revocation-via-transactional-outbox--rabbitmq)
4. [Standalone OCSP Client & Relying Party Verification Flow](#4-standalone-ocsp-client--relying-party-verification-flow)
5. [Authentication, Authorization & Console Security](#5-authentication-authorization--console-security)
6. [Database Data Models (ERDs)](#6-database-data-models-erds)
7. [RabbitMQ Messaging Topology](#7-rabbitmq-messaging-topology)
8. [Deployment Blueprint (Docker Compose Topology)](#8-deployment-blueprint-docker-compose-topology)
9. [Security & Cryptographic Boundary Diagram](#9-security--cryptographic-boundary-diagram)

---

## 1. Target System Blueprint

```mermaid
graph TB
    subgraph EXTERNAL["External Relying Parties & Operators"]
        RP["🌐 Relying Parties<br/>(TLS Clients, Browsers, mTLS Gateways)"]
        CLIENT_USER["💻 Client Testers<br/>http://localhost:8082"]
        OPS["👤 Security Operators<br/>Mantine Web Console :3000"]
    end

    subgraph KMS_ZONE["KMS Simulator Zone (:8090)"]
        KMS["kms-simulator<br/>────────────────<br/>• Web Management UI (:8090)<br/>• Certificate Authority Inventory<br/>• Test PKI Seeder (/data/pki)<br/>• Scheduled / Manual Revocations<br/>• Transactional Outbox Relay"]
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

    subgraph RESPONDER_APP["OCSP Responder Service (ocsp-responder :8080)"]
        subgraph SECURITY_LAYER["Spring Security & Auth Gate"]
            AUTH_CTRL["AuthController<br/>POST /api/v1/auth/login<br/>GET /api/v1/auth/me"]
            API_KEY_FILTER["ApiKeyAuthFilter<br/>X-API-KEY validation"]
            BASIC_AUTH["HttpBasicFilter<br/>admin / changeme"]
            SEC_CONFIG["SecurityConfig<br/>Public: /ocsp, /auth/**<br/>Protected: /api/v1/admin/**"]
        end

        subgraph RESP_CONTROLLERS["Protocol & Admin Controllers"]
            RESP_CTRL["OcspResponderController<br/>POST /ocsp (DER)<br/>GET /ocsp/{base64url}"]
            ADMIN_CTRL["Admin / Feed / CertCheck<br/>/api/v1/admin/**"]
            STATIC_LOGIN["Static Login Tester<br/>GET /login.html"]
        end

        subgraph RESP_SERVICES["Business Logic & Messaging"]
            RESP_SVC["OcspResponderService<br/>RFC 6960 parsing & assembly"]
            STATUS_SVC["CertificateStatusService<br/>Direct DB lookup & sequence check"]
            LISTENER["CertificateStatusListener<br/>@RabbitListener consumer"]
        end

        subgraph HSM_ZONE["SoftHSM2 Token (PKCS#11) 🔒"]
            TOKEN["SoftHSM2 Token: ocsp-signing<br/>• Delegated Signing Key (RSA 3072)<br/>• Non-extractable Private Key<br/>• Delegated OCSP Certificate"]
        end

        RESP_CTRL --> RESP_SVC
        ADMIN_CTRL --> STATUS_SVC
        ADMIN_CTRL --> RESP_SVC

        RESP_SVC --> STATUS_SVC
        RESP_SVC --> TOKEN
        LISTENER --> STATUS_SVC
    end

    subgraph CLIENT_APP["OCSP Client & Verifier Service (ocsp-client :8082)"]
        CLIENT_UI["Embedded Test Web UI<br/>http://localhost:8082"]
        CLIENT_CTRL["OcspClientController<br/>POST /api/v1/client/check"]
        CLIENT_SVC["OcspClientService<br/>• RFC 6960 Request Generator<br/>• Nonce Injector (Optional)<br/>• HTTP POST/GET Transporter<br/>• CA Signature Validator<br/>• Nonce Echo Matcher"]
        CLIENT_UI --> CLIENT_CTRL
        CLIENT_CTRL --> CLIENT_SVC
    end

    subgraph DB["OCSP Data Layer (:3307)"]
        OCSP_DB[("MariaDB<br/>schema: ocsp<br/>• revocation_status<br/>• ocsp_signing_cert")]
        STATUS_SVC --> OCSP_DB
    end

    subgraph CONSOLE["Frontend Web Console (:3000)"]
        LOGIN_PAGE["LoginPage (/login)<br/>Credentials / API Key Tabs"]
        PROT_ROUTE["ProtectedRoute<br/>AuthContext & Session Guard"]
        REACT["Mantine UI v7 Console<br/>Dashboard, KMS Inventory, Live Tests"]
        LOGIN_PAGE --> PROT_ROUTE --> REACT
    end

    RP --> RESP_CTRL
    CLIENT_USER --> CLIENT_UI
    CLIENT_SVC -->|RFC 6960 /ocsp| RESP_CTRL
    OPS --> LOGIN_PAGE
    REACT -->|Admin API + Auth| RESPONDER_APP
    REACT -->|Client Test Check| CLIENT_APP
    REACT -->|KMS Management| KMS
    KMS -- "Transactional Outbox Relay" --> EXCHANGE
    QUEUE --> LISTENER
```

---

## 2. Sequence: OCSP Request Processing & PKCS#11 Dynamic Signing

Every OCSP request (whether containing a nonce or nonce-free) queries the MariaDB `revocation_status` table directly and is dynamically signed by SoftHSM2 via PKCS#11. Responses are generated on-the-fly without stale cache windows, guaranteeing instantaneous consistency with revocations emitted via RabbitMQ.

```mermaid
sequenceDiagram
    autonumber
    actor Client as Relying Party (OpenSSL / ocsp-client)
    participant Ctrl as OcspResponderController (:8080)
    participant Svc as OcspResponderService
    participant DB_Svc as CertificateStatusService
    participant DB as MariaDB (schema: ocsp)
    participant Signer as Pkcs11OcspSigner
    participant HSM as SoftHSM2 (libsofthsm2.so)

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

Zero HTTP reconciliation or polling is performed. All revocation mutations in KMS are atomically persisted alongside an outbox event, asynchronously relayed to RabbitMQ, and ingested in real time by the Responder.

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Operator / Scheduled Simulation Job
    participant KMS as kms-simulator (:8090)
    participant KMS_DB as MariaDB (schema: kms)
    participant Relay as RabbitMqOutboxRelayAdapter
    participant Rabbit as RabbitMQ (Exchange: incert.certificate.status)
    participant Listener as CertificateStatusListener (ocsp-responder :8080)
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

## 4. Standalone OCSP Client & Relying Party Verification Flow

The `ocsp-client` application is an independent service running on port `8082` that acts as a real-world relying party:

1. **RFC 6960 Request Construction**:
   - Computes SHA-1 hash over Issuer Name and Public Key to generate the `CertID`.
   - Injects a cryptographically secure 16-byte random Nonce when configured.
2. **Transport Layer Flexibility**:
   - Supports both HTTP `POST` (binary DER body with `Content-Type: application/ocsp-request`) and HTTP `GET` (RFC 6960 Appendix A `/{base64url}` format).
3. **Response Validation**:
   - Verifies response status code `SUCCESSFUL`.
   - Cryptographically validates the RSA-3072 signature against the trusted CA certificate loaded at `/data/pki/intermediate-ca-cert.pem`.
   - Validates RFC 6960 §4.2.2.2 requirements (delegated signer certificate contains `id-kp-OCSPSigning` Extended Key Usage and is signed by the CA).
   - Validates temporal freshness: `thisUpdate <= now <= nextUpdate`.
   - Validates Nonce matching: verifies that `nonceSent == nonceEchoed`.
4. **Interactive Web Interface**:
   - Serves an embedded UI at `http://localhost:8082` with toggles for Nonce (ON/OFF), HTTP Method (POST/GET), and presets for rapid verification.

---

## 5. Authentication, Authorization & Console Security

Administrative access to the subsystem is guarded by a multi-layered security architecture:

```mermaid
graph TD
    subgraph INGRESS["Client / Browser Ingress"]
        REQ["Incoming HTTP Request"]
    end

    subgraph GATE["Spring Security Gate (ocsp-responder)"]
        PATH_CHECK{"Request Path?"}
        PUBLIC_PATH["/ocsp, /ocsp/**<br/>/actuator/health<br/>/api/v1/auth/**<br/>/login.html"]
        ADMIN_PATH["/api/v1/admin/**"]

        AUTH_FILTER{"Auth Header Present?"}
        API_KEY["X-API-KEY: incert-admin-secret-key"]
        BASIC["Authorization: Basic admin:changeme"]
        ANONYMOUS["No Auth Header"]

        ALLOW["200 OK / Process Request"]
        DENY["401 Unauthorized"]
    end

    REQ --> PATH_CHECK
    PATH_CHECK -->|Public Endpoint| PUBLIC_PATH --> ALLOW
    PATH_CHECK -->|Admin Endpoint| ADMIN_PATH --> AUTH_FILTER
    AUTH_FILTER -->|Matches API Key| ALLOW
    AUTH_FILTER -->|Matches Basic Auth| ALLOW
    AUTH_FILTER -->|Invalid / Missing| DENY
```

### Security Layers:
1. **RFC 6960 Public Endpoint**: `/ocsp` and `/ocsp/**` remain unauthenticated and globally reachable.
2. **Admin API Security**: `/api/v1/admin/**` requires `ROLE_ADMIN`, authenticated via `X-API-KEY: incert-admin-secret-key` or HTTP Basic (`admin` / `changeme`).
3. **Mantine Web Console Gate**:
   - The React SPA enforces authentication via `<ProtectedRoute>` around all dashboard views.
   - Users authenticate on the `/login` page with username/password or API key.
   - Stored credentials in `localStorage` are automatically injected into Axios requests.
   - Any `401 Unauthorized` response immediately flushes local state and redirects to `/login`.

---

## 6. Database Data Models (ERDs)

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
        VARCHAR(256) event_key
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

## 7. RabbitMQ Messaging Topology

| Component | Identifier | Details |
|---|---|---|
| **Direct Exchange** | `incert.certificate.status` | Durable direct exchange for PKI events |
| **Routing Key** | `incert.certificate.status.v1` | Routing key for status update events |
| **Durable Queue** | `ocsp.certificate.status` | Consumer queue with DLX bound |
| **Dead-Letter Exchange (DLX)** | `incert.certificate.status.dlx` | Direct exchange for rejected/poison messages |
| **Dead-Letter Queue (DLQ)** | `ocsp.certificate.status.dlq` | Durable queue capturing failed consumer deliveries |

---

## 8. Deployment Blueprint (Docker Compose Topology)

```mermaid
graph LR
    subgraph DOCKER_COMPOSE["Docker Compose Environment (Network: ocsp-net)"]
        MARIADB["ocsp-mariadb<br/>mariadb:10.11<br/>Port 3307:3306<br/>Schemas: ocsp, kms"]
        RABBIT["ocsp-rabbitmq<br/>rabbitmq:3.13-management<br/>Ports 5672, 15672"]
        KMS_SVC["ocsp-kms<br/>kms-simulator:local<br/>Port 8090:8090<br/>UI & Outbox Relay"]
        RESP_SVC["ocsp-responder<br/>ocsp/responder:local<br/>Port 8080:8080<br/>SoftHSM2 + Auth"]
        CLIENT_SVC["ocsp-client<br/>ocsp/client:local<br/>Port 8082:8082<br/>Verifier & Test UI"]
        CONSOLE_SVC["ocsp-console<br/>ocsp/console:local<br/>Port 3000:80<br/>Mantine UI v7"]
    end

    RESP_SVC --> MARIADB
    RESP_SVC --> RABBIT
    KMS_SVC --> MARIADB
    KMS_SVC --> RABBIT
    CONSOLE_SVC -->|/api/ -> :8080| RESP_SVC
    CONSOLE_SVC -->|/api/v1/client/ -> :8082| CLIENT_SVC
    CONSOLE_SVC -->|/api/kms/ -> :8090| KMS_SVC
    CLIENT_SVC -->|/ocsp -> :8080| RESP_SVC
```

---

## 9. Security & Cryptographic Boundary Diagram

```mermaid
graph TD
    subgraph CONTAINER["ocsp-responder Container Sandbox Boundary"]
        subgraph PROCESS["JVM (Java 21)"]
            APP_CODE["Responder Code (Protocol + Admin + Auth)"]
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
