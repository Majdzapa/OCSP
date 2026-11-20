# Incert OCSP Subsystem — Architecture & Blueprint (v5.0)

> **Version**: 5.0 · **Architecture**: Decoupled Standalone Services & Zero-REST RabbitMQ Event Bus · **Stack**: Java 25 · Spring Boot 4.0 · RabbitMQ 3.13 (Strict mTLS) · SoftHSM2 (PKCS#11) · Keycloak 24 · MariaDB 10.11 · React 18 · Mantine UI v7

---

## Table of Contents
1. [Target System Blueprint](#1-target-system-blueprint)
2. [Sequence: Multi-CA OCSP Request Processing & PKCS#11 Dynamic Signing](#2-sequence-multi-ca-ocsp-request-processing--pkcs11-dynamic-signing)
3. [Sequence: HSM CSR Generation, KMS CA Issuance & Post-Commit Signer Activation](#3-sequence-hsm-csr-generation-kms-ca-issuance--post-commit-signer-activation)
4. [Sequence: Transactional Outbox, Inbox Failure Tracking & Zero-REST RabbitMQ Reconciliation](#4-sequence-transactional-outbox-inbox-failure-tracking--zero-rest-rabbitmq-reconciliation)
5. [Standalone OCSP Client & Relying Party Verification Flow](#5-standalone-ocsp-client--relying-party-verification-flow)
6. [Authentication, Authorization & Runtime TLS Management](#6-authentication-authorization--runtime-tls-management)
7. [Database Data Models (ERDs)](#7-database-data-models-erds)
8. [RabbitMQ Messaging Topology & mTLS](#8-rabbitmq-messaging-topology--mtls)
9. [Deployment Blueprint (Docker Compose Topology)](#9-deployment-blueprint-docker-compose-topology)
10. [Security & Cryptographic HSM Boundary](#10-security--cryptographic-hsm-boundary)
11. [Pragmatic Layered Architecture & Pluggable Boundary Adapters](#11-pragmatic-layered-architecture--pluggable-boundary-adapters)

---

## 1. Target System Blueprint

```mermaid
graph TB
    subgraph EXTERNAL["External Relying Parties & Operators"]
        RP["Relying Parties<br/>(TLS Clients, Browsers, mTLS Gateways)"]
        CLIENT_USER["Client Testers<br/>http://localhost:8082"]
        OPS["OCSP Operators<br/>OCSP Console :3000"]
        KMS_OPS["PKI Operators<br/>KMS Console :3001"]
    end

    subgraph KMS_ZONE["KMS Simulator Zone (:8090 / :3001 / :3308)"]
        KMS_UI["kms-console (:3001)<br/>React 18 + Mantine v7<br/>• Certificate Authorities (/cas)<br/>• Certificate Inventory (/)<br/>• Outbox Monitor (/outbox)"]
        KMS["kms-simulator (:8090)<br/>────────────────<br/>• CertificateAuthorityService (Root & Sub CAs)<br/>• CSR Proof-of-Possession & Cert Issuance<br/>• RevocationService (Revoke / Hold / Unrevoke)<br/>• OutboxRelayService (500ms @Scheduled)<br/>• KmsReconciliationService (3s Manifest & Replay)"]
        KMS_DB[("kms-mariadb (:3308)<br/>schema: kms<br/>• certificate_authority<br/>• certificate<br/>• outbox_event")]
        KMS_UI -->|/api/kms/**| KMS
        KMS --> KMS_DB
    end

    subgraph BROKER["Message Broker (RabbitMQ :5671 mTLS / :5672 / :15672)"]
        EXCHANGE["Direct Exchange: incert.certificate.status"]
        QUEUE_STATUS["Queue: ocsp.certificate.status<br/>Routing Key: incert.certificate.status.v1"]
        QUEUE_MANIFEST["Queue: ocsp.reconciliation.manifest<br/>Routing Key: incert.reconciliation.manifest.v1"]
        QUEUE_REQ["Queue: kms.reconciliation.request<br/>Routing Key: incert.reconciliation.request.v1"]
        DLX["DLX: incert.certificate.status.dlx"]
        DLQ["DLQ: ocsp.certificate.status.dlq"]
        EXCHANGE --> QUEUE_STATUS
        EXCHANGE --> QUEUE_MANIFEST
        EXCHANGE --> QUEUE_REQ
        QUEUE_STATUS -.->|Dead-Letter on Rollback| DLX --> DLQ
    end

    subgraph IAM["Identity & Access Management"]
        KEYCLOAK["Keycloak (:8081)<br/>Realm: incert<br/>Groups: administrators, operators, auditors"]
    end

    subgraph RESPONDER_APP["OCSP Responder Service (ocsp-responder :8080)"]
        subgraph SECURITY_LAYER["Spring Security Gate (KEYCLOAK / SELF_MANAGED)"]
            AUTH_CTRL["AuthController<br/>/api/v1/auth/login, /config, /tls"]
            API_KEY_FILTER["ApiKeyAuthFilter<br/>X-API-KEY validation"]
            JWT_DECODER["KeycloakJwtAuthenticationConverter<br/>OAuth2 / OIDC Bearer JWT"]
        end

        subgraph RESP_CONTROLLERS["Protocol & Admin Controllers"]
            RESP_CTRL["OcspResponderController<br/>POST /ocsp (DER)<br/>GET /ocsp/{base64url}"]
            SIGN_CTRL["SigningCertificateController<br/>/api/v1/admin/signing-certificates/**"]
            INBOX_CTRL["InboxAdminController<br/>/api/v1/admin/inbox/**<br/>/api/v1/admin/reconciliation/**"]
            ADMIN_CTRL["AdminDashboard / CertCheck / Feed<br/>/api/v1/admin/**"]
        end

        subgraph RESP_SERVICES["Business Logic & Event Consumers"]
            RESP_SVC["OcspResponderService<br/>RFC 6960 Parser, Nonce & Response Builder"]
            SIGN_SVC["SigningCertificateService<br/>HSM CSR, Cert Import, AFTER_COMMIT Sync"]
            STATUS_SVC["CertificateStatusService<br/>CertID + Serial Fallback & Sequence Guard"]
            CONSUMER["CertificateStatusConsumerService<br/>Transactional Inbox & Idempotency"]
            FAIL_REC["InboxFailureRecorder<br/>REQUIRES_NEW Failure & AMQP Tag Logger"]
            RECON_SVC["OutboxReconciliationService<br/>Zero-REST Outbox vs Inbox Diff & Replay"]
            LISTENER["CertificateStatusListener<br/>@RabbitListener (MESSAGE_ID, DELIVERY_TAG)"]
            LISTENER --> CONSUMER
            CONSUMER --> STATUS_SVC
            CONSUMER --> FAIL_REC
        end

        subgraph HSM_ZONE["Cryptographic HSM Boundary"]
            SIGNER_IFACE["OcspSigner + SigningAlgorithm Enum<br/>(RSA & ECDSA Algorithms)"]
            PKCS11_ADAPTER["Pkcs11OcspSigner<br/>Multi-CA Signer Selection & SunPKCS11"]
            TOKEN["SoftHSM2 Token: ocsp-signing<br/>• Empty Token on Init (No Pre-Seeded Keys)<br/>• On-Demand Non-Extractable RSA/EC Keys"]
            SIGNER_IFACE --> PKCS11_ADAPTER
            PKCS11_ADAPTER --> TOKEN
        end

        RESP_CTRL --> RESP_SVC
        SIGN_CTRL --> SIGN_SVC
        INBOX_CTRL --> RECON_SVC
        ADMIN_CTRL --> STATUS_SVC
        RESP_SVC --> STATUS_SVC
        RESP_SVC --> SIGNER_IFACE
        SIGN_SVC --> SIGNER_IFACE
    end

    subgraph CLIENT_APP["OCSP Client & Verifier Service (ocsp-client :8082)"]
        CLIENT_UI["Embedded Test Web UI (:8082)"]
        CLIENT_CTRL["OcspClientController<br/>POST /api/v1/client/check"]
        CLIENT_SVC["OcspClientService<br/>• RFC 6960 CertID Builder (with issuerPem)<br/>• Optional 8-Byte Nonce<br/>• POST (DER) / GET (Base64URL)<br/>• CA & Delegated Responder Signature Verifier"]
        CLIENT_UI --> CLIENT_CTRL --> CLIENT_SVC
    end

    subgraph DB["OCSP Data Layer (:3307)"]
        OCSP_DB[("ocsp-mariadb (:3307)<br/>schema: ocsp<br/>• revocation_status<br/>• signing_certificates<br/>• inbox_event")]
        STATUS_SVC --> OCSP_DB
        SIGN_SVC --> OCSP_DB
        CONSUMER --> OCSP_DB
        FAIL_REC --> OCSP_DB
        RECON_SVC --> OCSP_DB
    end

    subgraph CONSOLE["OCSP Admin Console (:3000)"]
        OCSP_UI["ocsp-console (:3000)<br/>React 18 + Mantine v7<br/>• Dashboard & Revocations<br/>• Multi-CA Signing Certificates & HSM CSR<br/>• Live Inbox Audit (3s Auto-Refresh) & Replay<br/>• Cert Checker (with Issuer CA PEM)"]
    end

    RP --> RESP_CTRL
    CLIENT_USER --> CLIENT_UI
    CLIENT_SVC -->|RFC 6960 /ocsp| RESP_CTRL
    OPS --> OCSP_UI
    KMS_OPS --> KMS_UI
    OCSP_UI -->|Admin API + JWT/Key| RESPONDER_APP
    OCSP_UI -->|OIDC SSO| KEYCLOAK
    OCSP_UI -->|Live OCSP Check| CLIENT_APP
    JWT_DECODER -->|JWKS Validation| KEYCLOAK
    KMS -->|Publish Status & Manifest| EXCHANGE
    QUEUE_STATUS --> LISTENER
    QUEUE_MANIFEST --> RECON_SVC
    RECON_SVC -->|REQUEST_MANIFEST / REPLAY_EVENTS| EXCHANGE
    QUEUE_REQ --> KMS
```

---

## 2. Sequence: Multi-CA OCSP Request Processing & PKCS#11 Dynamic Signing

Every OCSP request is validated, matched against the issuing CA's active signing certificate (`OcspSigner.selectSigner(CertID)`), resolved directly from MariaDB (`revocation_status`), and signed inside SoftHSM2 via PKCS#11. If no signing certificate has been configured and activated yet, the responder returns RFC 6960 `TRY_LATER` (`status = 3`).

```mermaid
sequenceDiagram
    autonumber
    actor Client as Relying Party (OpenSSL / ocsp-client)
    participant Ctrl as OcspResponderController (:8080)
    participant Svc as OcspResponderService
    participant Signer as Pkcs11OcspSigner
    participant DB_Svc as CertificateStatusService
    participant DB as MariaDB (ocsp.revocation_status)
    participant HSM as SoftHSM2 (libsofthsm2.so)

    Client->>Ctrl: POST /ocsp (DER) or GET /ocsp/{base64url}
    Ctrl->>Svc: handle(derRequest)
    Svc->>Svc: Parse OCSPReq (max 10KB, max 10 CertIDs), validate Nonce (1..32 bytes)
    Svc->>Signer: selectSigner(requests[0].getCertID())

    alt No active signing certificate configured
        Signer-->>Svc: throw SignerNotConfiguredException
        Svc-->>Ctrl: OCSPResp (TRY_LATER = 3)
        Ctrl-->>Client: 200 OK (OCSPResponse status: tryLater)
    else Active signing certificate(s) available
        Signer->>Signer: Match CertID issuerNameHash + AuthorityKeyIdentifier (issuerKeyHash)
        Signer-->>Svc: SigningSelection(chain, ContentSigner for selected key/algorithm)

        loop For each CertID in request
            Svc->>DB_Svc: findByCertId(issuerNameHash, issuerKeyHash, serialBytes)
            DB_Svc->>DB: Strict RFC 6960 SELECT by (issuer_name_hash, issuer_key_hash, serial_number)
            DB-->>DB_Svc: Optional<RevocationStatus> (GOOD, REVOKED, or empty -> UNKNOWN)
            DB_Svc-->>Svc: Optional<RevocationStatus>
        end

        opt Nonce present in request
            Svc->>Svc: Echo Nonce extension in BasicOCSPResp (RFC 6960 §4.4.1)
        end

        Svc->>HSM: Sign BasicOCSPResp via SunPKCS11 (SigningAlgorithm: RSA or ECDSA)
        HSM-->>Svc: Cryptographic Signature Bytes
        Svc-->>Ctrl: OCSPResp (SUCCESSFUL = 0)
        Ctrl-->>Client: 200 OK (Content-Type: application/ocsp-response)
    end
```

---

## 3. Sequence: HSM CSR Generation, KMS CA Issuance & Post-Commit Signer Activation

Neither `ocsp-hsm` nor `kms-simulator` pre-seeds any keys, CAs, or certificates. Below is the complete end-to-end provisioning flow:

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Security Administrator
    participant OCSP as ocsp-responder (:8080)
    participant HSM as SoftHSM2 Token (ocsp-signing)
    participant OCSP_DB as MariaDB (ocsp.signing_certificates)
    participant KMS as kms-simulator (:8090)
    participant KMS_DB as MariaDB (kms)

    Admin->>KMS: POST /kms/cas (Create Root or Subordinate CA: RSA/EC)
    KMS->>KMS_DB: INSERT INTO certificate_authority (name, subject_dn, issuer_key_hash_hex, ...)
    KMS-->>Admin: 201 Created (CaDto + CA Certificate PEM)

    Admin->>OCSP: POST /api/v1/admin/signing-certificates/csr (keyLabel, subjectDn, RSA/EC, keySize)
    OCSP->>HSM: Generate non-extractable keypair in token (or reuse if reuseExistingKey=true)
    OCSP->>HSM: Sign PKCS#10 CSR with HSM PrivateKey
    OCSP-->>Admin: 200 OK (csrPem)

    Admin->>KMS: POST /kms/cas/{caId}/certificates (csrPem, profile="OCSP_SIGNING")
    KMS->>KMS: Verify CSR signature (proof-of-possession)
    KMS->>KMS: Sign X.509 cert (EKU: id-kp-OCSPSigning + id-pkix-ocsp-nocheck)
    KMS->>KMS_DB: INSERT INTO certificate (status='GOOD') + outbox_event
    KMS-->>Admin: 201 Created (IssuedCertificateDto: certificatePem, chainPem)

    Admin->>OCSP: POST /api/v1/admin/signing-certificates (alias, keyLabel, certificatePem, signatureAlgorithm, activateImmediately=true)
    OCSP->>OCSP: Validate expiry & SigningAlgorithm compatibility with RSA/EC key type
    OCSP->>HSM: Verify cert PublicKey matches HSM keyLabel & bind cert in PKCS#11 KeyStore
    OCSP->>OCSP_DB: INSERT INTO signing_certificates (active=true, activated_at=now)
    Note over OCSP,HSM: @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    OCSP->>HSM: updateActiveCertificate() & syncRegisteredSigners() after DB commit
    OCSP-->>Admin: 201 Created (SigningCertificateDto)
```

---

## 4. Sequence: Transactional Outbox, Inbox Failure Tracking & Zero-REST RabbitMQ Reconciliation

All communication between `kms-simulator` and `ocsp-responder` happens exclusively over RabbitMQ (zero HTTP/REST calls between the two services).

```mermaid
sequenceDiagram
    autonumber
    participant KMS as kms-simulator (:8090)
    participant KMS_DB as MariaDB (kms.outbox_event)
    participant Rabbit as RabbitMQ (incert.certificate.status)
    participant Listener as CertificateStatusListener
    participant Consumer as CertificateStatusConsumerService
    participant FailRec as InboxFailureRecorder (REQUIRES_NEW)
    participant Recon as OutboxReconciliationService
    participant OCSP_DB as MariaDB (ocsp.inbox_event & revocation_status)

    Note over KMS,KMS_DB: 1. Certificate Issuance / Revocation / Hold / Unrevoke
    KMS->>KMS_DB: Commit Certificate change -> @TransactionalEventListener(AFTER_COMMIT) writes outbox_event
    loop OutboxRelayService every 500ms (and immediately on mutation)
        KMS->>Rabbit: Publish CertificateStatusChanged (AMQP messageId = outbox_event.event_id)
        KMS->>KMS_DB: UPDATE outbox_event SET sent=true, sent_at=now
    end

    Note over Rabbit,OCSP_DB: 2. Transactional Inbox Consumption & Failure Traceability
    Rabbit->>Listener: Deliver message (MESSAGE_ID, DELIVERY_TAG, CONSUMER_QUEUE, REDELIVERED)
    Listener->>Consumer: consume(payload, messageId, deliveryTag, consumerQueue, redelivered)
    alt Valid JSON & Processing Succeeds
        Consumer->>OCSP_DB: Save inbox_event (PROCESSED / DUPLICATE / SKIPPED) + update revocation_status
    else Malformed JSON or Processing Exception
        Consumer->>FailRec: recordFailure(messageId, ..., deliveryTag, consumerQueue, redelivered, error)
        FailRec->>OCSP_DB: Commit FAILED row in independent REQUIRES_NEW transaction (event_id = messageId)
        Consumer-->>Rabbit: Throw RuntimeException -> Rollback main TX & route message to DLQ
    end

    Note over KMS,Recon: 3. Purely RabbitMQ-Based Outbox <-> Inbox Reconciliation & Self-Healing Replay
    loop KmsReconciliationService every 3000ms (or on REQUEST_MANIFEST)
        KMS->>Rabbit: Publish OutboxManifestEvent (routing key: incert.reconciliation.manifest.v1)
        Rabbit->>Recon: onOutboxManifest() caches latest OutboxManifestEvent
    end
    Recon->>OCSP_DB: Compare manifest outboxEventIds & certificate digests vs inbox_event & revocation_status
    opt Discrepancy found or Operator clicks "Replay via RabbitMQ" (POST /api/v1/admin/reconciliation/replay)
        Recon->>Rabbit: Publish ReconciliationCommandMessage(REPLAY_EVENTS, missingEventIds, missingSerials)
        Rabbit->>KMS: onReconciliationCommand() re-publishes matching outbox_event rows & fresh manifest
    end
```

---

## 5. Standalone OCSP Client & Relying Party Verification Flow

`ocsp-client` (`:8082`) is a standalone relying-party service and interactive test UI:
1. **RFC 6960 Request Construction**:
   - Accepts the target certificate (or `serialHex`) and the issuing CA certificate (`issuerPem`, pasted once in **OCSP Console -> Cert Checker** and persisted in browser `localStorage`, or submitted via `/api/v1/client/check`).
   - Computes SHA-1 `issuerNameHash` and `issuerKeyHash` to construct the `CertID`.
   - Optionally injects an 8-byte cryptographically random Nonce extension (`1.3.6.1.5.5.7.48.1.2`).
2. **Transport Support**:
   - HTTP `POST /ocsp` (`Content-Type: application/ocsp-request`)
   - HTTP `GET /ocsp/{base64UrlEncodedRequest}`
3. **Cryptographic & RFC 6960 Verification**:
   - Verifies OCSP response status (`SUCCESSFUL`, `TRY_LATER`, `MALFORMED_REQUEST`, etc.).
   - Validates the responder's digital signature (RSA or ECDSA) against the issuing CA certificate or a delegated OCSP responder certificate signed by the CA with `id-kp-OCSPSigning`.
   - Verifies validity window (`thisUpdate` / `nextUpdate`) and exact Nonce echo (`nonceSent == nonceEchoed`).

---

## 6. Authentication, Authorization & Runtime TLS Management

- **Dual Authentication Modes (`security.auth-mode`)**:
  - **`KEYCLOAK` (default in Docker)**: Validates OAuth2 / OIDC Bearer JWTs issued by Keycloak (`http://localhost:8081/realms/incert`) and maps Keycloak groups (`/ocsp-administrators`, `/ocsp-operators`, `/ocsp-auditors`) to Spring Security roles.
  - **`SELF_MANAGED`**: Local credential authentication without requiring an external Keycloak instance.
- **Machine & Break-Glass Access**:
  - `X-API-KEY: incert-admin-secret-key`
  - HTTP Basic Auth (`admin:changeme`)
- **Runtime Login TLS Activation / Deactivation**:
  - `GET /api/v1/auth/tls` and `POST /api/v1/auth/tls` (`{"enabled": true|false}`) allow toggling mTLS client-certificate login (`POST /api/v1/auth/login` with `clientCert`) at runtime without restarting `ocsp-responder`.

---

## 7. Database Data Models (ERDs)

```mermaid
erDiagram
    %% KMS Schema (kms-mariadb :3308)
    KMS_CERTIFICATE_AUTHORITY {
        BIGINT id PK
        VARCHAR(128) name UK
        VARCHAR(512) subject_dn
        BIGINT parent_id
        VARCHAR(16) key_algorithm
        VARCHAR(32) signature_algorithm
        VARCHAR(40) issuer_key_hash_hex
        VARCHAR(40) issuer_name_hash_hex
        MEDIUMTEXT certificate_pem
        MEDIUMTEXT private_key_pem
        DATETIME not_before
        DATETIME not_after
        DATETIME created_at
    }

    KMS_CERTIFICATE {
        BIGINT id PK
        VARCHAR(128) serial_number_hex UK
        VARCHAR(512) issuer_dn
        VARCHAR(40) issuer_key_hash_hex
        VARCHAR(40) issuer_name_hash_hex
        VARCHAR(512) subject_dn
        DATETIME not_before
        DATETIME not_after
        ENUM status
        DATETIME revocation_time
        VARCHAR(30) revocation_reason
        MEDIUMTEXT pem_encoded
        BIGINT sequence
        BIGINT ca_id FK
        DATETIME updated_at
    }

    KMS_OUTBOX_EVENT {
        VARCHAR(64) event_id PK
        VARCHAR(128) topic
        VARCHAR(256) event_key
        TEXT payload
        DATETIME created_at
        DATETIME sent_at
        BOOLEAN sent
    }

    KMS_CERTIFICATE_AUTHORITY ||--o{ KMS_CERTIFICATE : "issues"

    %% OCSP Schema (ocsp-mariadb :3307)
    OCSP_REVOCATION_STATUS {
        BIGINT id PK
        BINARY(20) issuer_name_hash
        BINARY(20) issuer_key_hash
        VARBINARY(64) serial_number
        ENUM status
        DATETIME revocation_time
        VARCHAR(40) revocation_reason
        DATETIME this_update
        DATETIME updated_at
        VARCHAR(64) source_event_id UK
        BIGINT sequence
    }

    OCSP_SIGNING_CERTIFICATES {
        BIGINT id PK
        VARCHAR(128) alias UK
        VARCHAR(128) key_label
        VARCHAR(512) subject_dn
        VARCHAR(512) issuer_dn
        VARCHAR(128) serial_number
        DATETIME not_before
        DATETIME not_after
        VARCHAR(64) signature_algorithm
        TEXT certificate_pem
        BOOLEAN active
        DATETIME created_at
        DATETIME activated_at
    }

    OCSP_INBOX_EVENT {
        VARCHAR(64) event_id PK
        VARCHAR(64) event_type
        VARCHAR(128) certificate_serial
        VARCHAR(32) status
        VARCHAR(64) revocation_reason
        DATETIME revocation_time
        BIGINT sequence
        TEXT payload
        DATETIME received_at
        DATETIME processed_at
        VARCHAR(32) processing_status
        TEXT error_message
        BIGINT delivery_tag
        VARCHAR(128) consumer_queue
        BOOLEAN redelivered
    }
```

---

## 8. RabbitMQ Messaging Topology & mTLS

| Component | Identifier | Purpose |
|---|---|---|
| **Direct Exchange** | `incert.certificate.status` | Durable direct exchange shared by KMS and OCSP Responder |
| **Status Queue & Key** | Queue: `ocsp.certificate.status`<br>Key: `incert.certificate.status.v1` | Carries `CertificateStatusChanged` events (`AMQP messageId = outbox_event.event_id`) from KMS to OCSP Responder |
| **Dead-Letter Exchange & Queue** | DLX: `incert.certificate.status.dlx`<br>DLQ: `ocsp.certificate.status.dlq` | Captures poison/malformed messages rejected by `CertificateStatusConsumerService` (while `InboxFailureRecorder` records a `FAILED` row in `ocsp.inbox_event`) |
| **Reconciliation Manifest Queue & Key** | Queue: `ocsp.reconciliation.manifest`<br>Key: `incert.reconciliation.manifest.v1` | Carries `OutboxManifestEvent` broadcasts (every 3s and on demand) from KMS to OCSP Responder |
| **Reconciliation Command Queue & Key** | Queue: `kms.reconciliation.request`<br>Key: `incert.reconciliation.request.v1` | Carries `ReconciliationCommandMessage` (`REQUEST_MANIFEST` / `REPLAY_EVENTS`) from OCSP Responder to KMS |
| **Transport Security** | Port `5671` (mTLS) / Port `5672` (Plaintext) / Port `15672` (Management UI) | Strict mutual TLS by default (`RABBITMQ_TLS_ENABLED=true`); automatic fallback to `5672` when `false`. Broker credentials: `ocsp_amqp` / `changeme`. |

---

## 9. Deployment Blueprint (Docker Compose Topology)

The subsystem is deployed across two standalone Docker Compose stacks sharing the external bridge network `ocsp-net`:

1. **`OCSP/docker-compose.yml` (7 containers)**:
   - `ocsp-mariadb` (`:3307 -> 3306`, schema `ocsp`)
   - `ocsp-rabbitmq` (`:5671`, `:5672`, `:15672`)
   - `ocsp-keycloak` (`:8081`)
   - `ocsp-hsm` (SoftHSM2 container initializing empty token `ocsp-signing` on shared volumes `hsm-tokens` and `hsm-conf`)
   - `ocsp-responder` (`:8080`, mounts `hsm-tokens` and `hsm-conf` to access SoftHSM2 via `libsofthsm2.so`)
   - `ocsp-client` (`:8082`)
   - `ocsp-console` (`:3000 -> 80`)
2. **`kms-simulator/docker-compose.yml` (3 containers on `ocsp-net`)**:
   - `kms-mariadb` (`:3308 -> 3306`, schema `kms`)
   - `kms-simulator` (`:8090`)
   - `kms-console` (`:3001 -> 80`)

---

## 10. Security & Cryptographic HSM Boundary

```mermaid
graph TD
    subgraph HSM_CONTAINER["ocsp-hsm (Dedicated SoftHSM2 Container)"]
        HSM_INIT["init-hsm.sh<br/>Initializes Empty Token 'ocsp-signing'<br/>(Zero Pre-Seeded Keys or Certificates)"]
        SHARED_TOKENS["Shared Docker Volumes<br/>/var/lib/softhsm/tokens<br/>/etc/softhsm2/softhsm2.conf"]
        HSM_INIT --> SHARED_TOKENS
    end

    subgraph RESP_CONTAINER["ocsp-responder Container Boundary"]
        subgraph PROCESS["JVM (Java 25)"]
            SIGN_SVC["SigningCertificateService<br/>• generateCsr()<br/>• addCertificate() / activate()<br/>• @TransactionalEventListener(AFTER_COMMIT)"]
            PKCS11["Pkcs11OcspSigner + SunPKCS11 Provider<br/>• On-Demand Keypair & CSR Generation<br/>• Public Key Match Verification on Import<br/>• Multi-CA Signer Selection (CertID)"]
            SIGN_SVC --> PKCS11
        end
        LIB["libsofthsm2.so"]
        PKCS11 --> LIB
    end

    SHARED_TOKENS -.->|Mounted Read/Write| LIB
    SHARED_TOKENS --- PRIV_KEY["HSM Private Keys (RSA 2048/3072/4096, EC P-256/P-384)<br/>Generated On-Demand Inside Token<br/>Non-Extractable Private Key Material"]
```

- **Zero Pre-Seeded Keys**: `init-hsm.sh` initializes only the SoftHSM2 slot/token (`ocsp-signing`). All signing keys are created on demand by the administrator via `generateCsr` and bound to CA-issued certificates via `importCertificateToToken`.
- **Production Guard (`@Profile("!prod")`)**: `SoftwareKeyOcspSigner` is disabled in the `prod` profile; production deployments strictly require PKCS#11 HSM connectivity.
- **Post-Commit Consistency**: In-memory HSM signer state is updated via `@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)` so a database rollback can never leave the HSM signer and `ocsp.signing_certificates` out of sync.

---

## 11. Pragmatic Layered Architecture & Pluggable Boundary Adapters

The codebase uses standard Spring layered architecture (`controller` -> `service` -> `repository`) and places interfaces strictly at external infrastructure boundaries:

1. **Cryptographic HSM Adapter (`OcspSigner`)**:
   - Implemented by `Pkcs11OcspSigner` (SoftHSM2 / hardware PKCS#11 HSM) and `SoftwareKeyOcspSigner` (`@Profile("!prod")` test fallback), backed by the centralized `SigningAlgorithm` enum.
2. **Event Publisher Adapter (`CertificateEventPublisher`)**:
   - Implemented by `RabbitMqCertificateEventPublisher` (sets AMQP `messageId = eventId` for end-to-end Outbox–Inbox traceability).
3. **Event Consumer Adapter (`CertificateStatusConsumer`)**:
   - Invoked by `CertificateStatusListener` (`@RabbitListener`) and implemented by `CertificateStatusConsumerService` + `InboxFailureRecorder` (`Propagation.REQUIRES_NEW`).
