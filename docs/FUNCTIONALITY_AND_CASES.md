# Incert OCSP Subsystem — Functionality & Cases Reference

This document provides a complete, structured reference of all implemented features, operational workflows, and edge/failure cases across the Incert OCSP Subsystem (`ocsp-responder`, `ocsp-console`, `ocsp-client`, `kms-simulator`, `hsm`, `rabbitmq`, `keycloak`, and `mariadb`).

---

## 1. System Modules & Responsibilities

| Module | Port | Responsibility |
|---|---|---|
| **`ocsp-responder`** | `8080` | RFC 6960 OCSP protocol endpoint, PKCS#11 HSM signing, multi-CA signing cert registry, RabbitMQ inbox consumer, Admin & Reconciliation APIs, dual-mode Spring Security |
| **`ocsp-console`** | `3000` | React 18 + Mantine v7 Admin Dashboard (Dashboard, Signing Certificates, Revocations, Inbox Audit, Reconciliation) |
| **`ocsp-client`** | `8082` | Standalone RFC 6960 test client & web UI (POST/GET, Nonce, signature verification against CA/trusted responder certs) |
| **`kms-simulator`** | `8090` | Certificate lifecycle source of truth, test PKI generator, Transactional Outbox (`outbox_event`), RabbitMQ publisher |
| **`hsm` (SoftHSM2)** | N/A | Dedicated PKCS#11 token container storing non-extractable RSA/EC signing keys |
| **`rabbitmq`** | `5671` / `5672` / `15672` | AMQPS (mTLS) & AMQP event bus + Management UI (`ocsp_amqp` / `changeme`) |
| **`keycloak`** | `8081` | OAuth2 / OIDC IAM (`incert` realm, `ocsp-console` client, groups & roles) |
| **`mariadb`** | `3307` (host) | Persistent storage (`ocsp` and `kms` schemas) |

---

## 2. RFC 6960 OCSP Responder Protocol

### Endpoints
- `POST /ocsp` (`application/ocsp-request` -> `application/ocsp-response`)
- `GET /ocsp/{base64UrlEncodedRequest}`

### Supported Cases
1. **Certificate Status Resolution**:
   - **`GOOD`**: Certificate exists and is active/valid.
   - **`REVOKED`**: Certificate is revoked, returning revocation time and `RevocationReason`.
   - **`UNKNOWN`**: Serial number not found in `revocation_status`.
   - **Issuer Hash Fallback**: If `CertID` issuer hash differs from the KMS seed, `ocsp-responder` falls back to serial-number lookup.
2. **Nonce Extension**:
   - If the request includes an OCSP Nonce extension, the response echoes the exact nonce bytes to prevent replay attacks.
3. **Protocol Error Handling**:
   - Invalid Base64 in `GET /ocsp` or malformed DER ASN.1 returns an RFC 6960 `MALFORMED_REQUEST` OCSP response (or `TRY_LATER` on internal/signer unavailability).
4. **Signature Verification (`ocsp-client`)**:
   - Verifies response signatures against either the issuing CA certificate or a configured trusted delegated OCSP responder certificate.

---

## 3. Multi-CA & Dynamic Signing Certificate Management

### Key Capabilities
1. **Multiple Simultaneously Active Signing Certificates**:
   - Multiple signing certificates (e.g., for different CAs or key types) can be active at the same time in `signing_certificates`.
   - On each OCSP request, `OcspResponderService` calls `signer.selectSigner(requests[0].getCertID())` to match the request's `CertID` (`issuerNameHash` / `issuerKeyHash` / public key) to the right active signing certificate, falling back to the primary active signer when no specific match is needed.
2. **Centralized `SigningAlgorithm` Enum**:
   - RSA algorithms: `SHA256withRSA`, `SHA384withRSA`, `SHA512withRSA`, `SHA256withRSAandMGF1`.
   - ECDSA algorithms: `SHA256withECDSA`, `SHA384withECDSA`, `SHA512withECDSA`.
   - `GET /api/v1/admin/signing-certificates/hsm-info` exposes available HSM key labels, key types, and compatible `SigningAlgorithm` values so the Console UI filters signature algorithms by the selected HSM key type.
3. **HSM Token Initialization, CSR Generation & Certificate Import**:
   - `init-hsm.sh` only initializes an empty SoftHSM2 token (`ocsp-signing`); no static CA, keypair, or default signing certificate is pre-provisioned.
   - Until a user imports and activates a signing certificate, `/ocsp` responds with RFC 6960 `TRY_LATER` (`SignerNotConfiguredException`).
   - `POST /api/v1/admin/signing-certificates/csr` generates a new RSA (`2048`/`3072`/`4096`) or EC (`256`/`384`) keypair inside the HSM token (or reuses an existing `keyLabel` when `reuseExistingKey=true`) and returns a signed PKCS#10 CSR.
   - In KMS Console (`http://localhost:3001/cas`), the user creates a Root/Subordinate CA (`POST /kms/cas`), issues the certificate from the CSR (`POST /kms/cas/{id}/certificates` with profile `OCSP_SIGNING`, `TLS_SERVER`, `TLS_CLIENT`, or `GENERIC`), and imports/activates it in OCSP Console (`POST /api/v1/admin/signing-certificates`).
4. **Production-Safe Commit Synchronization**:
   - `SigningCertificateService.activate(id)` pre-validates certificate expiration and HSM key existence (`ocspSigner.listKeyLabels()`), saves DB state, and publishes `SigningConfigurationChangedEvent`.
   - `@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)` updates the in-memory `OcspSigner` and syncs all active signers **only after the DB transaction commits**, preventing DB/HSM drift on rollback.
   - `SoftwareKeyOcspSigner` fallback is annotated with `@Profile("!prod")` so production deployments never fall back to an in-memory software key.

### Edge & Validation Cases
| Case | Behavior |
|---|---|
| Activate expired certificate | Rejected (`IllegalStateException`: `Cannot activate an expired certificate`) |
| Activate cert whose HSM `keyLabel` is missing from token | Rejected (`IllegalStateException`: `HSM key '...' not found in token`) |
| Deactivate a certificate while another remains active | Allowed; remaining most recently activated certificate becomes fallback default and HSM signer registry is resynced after commit |
| Deactivate the last remaining active certificate | Rejected (`IllegalStateException`: `Cannot deactivate the last remaining active signing certificate`) |
| Delete an active certificate | Rejected (`IllegalStateException`: `Cannot delete the currently active signing certificate`) |
| Request 1 signed by Active Cert 1 & Request 2 signed by Active Cert 2 | Supported; `selectSigner(CertID)` selects the matching active certificate per request |

---

## 4. Event-Driven Sync (Outbox -> RabbitMQ -> Inbox) & Traceability

### Normal Flow
1. **KMS Outbox (`kms-simulator`)**:
   - Certificate issuance/revocation writes atomically to `kms.outbox_event`.
   - `RabbitMqCertificateEventPublisher` publishes the JSON payload to RabbitMQ with `message.getMessageProperties().setMessageId(eventId)`.
2. **OCSP Inbox (`ocsp-responder`)**:
   - `CertificateStatusListener` receives the payload along with AMQP headers:
     - `AmqpHeaders.MESSAGE_ID`
     - `AmqpHeaders.DELIVERY_TAG`
     - `AmqpHeaders.CONSUMER_QUEUE`
     - `AmqpHeaders.REDELIVERED`
   - `CertificateStatusConsumerService.consume(...)` runs in a single `@Transactional` boundary covering `inbox_event` and `revocation_status`.

### Inbox Processing Statuses & Cases
| Status | Trigger / Case | Behavior |
|---|---|---|
| `RECEIVED` | Initial save before status application | Persisted with `delivery_tag`, `consumer_queue`, `redelivered` |
| `PROCESSED` | Valid event applied to `revocation_status` | Both `inbox_event` and `revocation_status` commit together |
| `DUPLICATE` | `event_id` already exists and is not `FAILED` | Updates `processing_status = DUPLICATE`, `processed_at`, and latest AMQP delivery metadata; skips re-applying status |
| `SKIPPED` | Older/out-of-order `sequence` | Recorded as `SKIPPED` without overwriting newer state |
| `FAILED` | JSON parse error or processing exception | Main transaction rolls back (enabling RabbitMQ DLQ routing), while `InboxFailureRecorder.recordFailure(...)` (`Propagation.REQUIRES_NEW`) commits a `FAILED` row |

### Outbox–Inbox Failure Link (`FAILED` Events)
- Even when a RabbitMQ message has **malformed JSON** (so `eventId` cannot be parsed from the body), `CertificateStatusListener` extracts `AmqpHeaders.MESSAGE_ID` and passes it to `InboxFailureRecorder`.
- `InboxFailureRecorder` stores:
  - `event_id`: `messageId` (matching `kms.outbox_event.event_id`), or `failed-<UUID>` only if `messageId` is absent.
  - `delivery_tag`, `consumer_queue`, `redelivered`: Exact RabbitMQ broker metadata for tracing & DLQ inspection.
  - `error_message`: Root exception message.
- Re-delivering a previously `FAILED` event with the same `event_id` is allowed to reprocess (idempotency check explicitly skips `DUPLICATE` marking when prior status is `FAILED`).

### Purely RabbitMQ-Based Outbox ↔ Inbox Reconciliation & Replay (Zero REST Calls)
- **Outbox Manifest Broadcast (`kms -> ocsp`)**:
  - `KmsReconciliationService` broadcasts `OutboxManifestEvent` to queue `ocsp.reconciliation.manifest` (`incert.reconciliation.manifest.v1`) every 3 seconds and on demand, carrying `outboxEventIds`, `totalOutboxEvents`, `sentOutboxEvents`, `pendingOutboxEvents`, and per-certificate `(serialNumberHex, status, revocationReason, sequence, latestEventId)` digests.
- **Outbox ↔ Inbox Verification (`GET /api/v1/admin/reconciliation/verify`)**:
  - `OutboxReconciliationService` compares the KMS Outbox manifest against `ocsp.inbox_event` and `ocsp.revocation_status` without any HTTP call to KMS, reporting:
    - `missingInInboxEventIds`: Outbox `event_id`s never received in `ocsp.inbox_event`.
    - `failedInInboxEventIds`: Inbox events with `processing_status = FAILED`.
    - `missingSerials` & `statusMismatches`: Certificates missing or out-of-date in `ocsp.revocation_status`.
- **Self-Healing Replay (`POST /api/v1/admin/reconciliation/replay`)**:
  - Publishes a `ReconciliationCommandMessage` (`command = "REPLAY_EVENTS"`) to queue `kms.reconciliation.request` (`incert.reconciliation.request.v1`) listing the missing/failed `eventId`s and `serialNumberHex`s.
  - `KmsReconciliationService` consumes the command and re-publishes the matching `kms.outbox_event` rows over RabbitMQ.
- **Live Inbox Audit (`InboxAuditPage.tsx`)**:
  - Automatically polls inbox events and Outbox ↔ Inbox reconciliation status every **3 seconds** when `Live Auto-Refresh (3s)` is enabled, and provides a one-click **Replay via RabbitMQ** button.

---

## 5. Authentication, Authorization & TLS Management

### Authentication Modes (`security.auth-mode`)
1. **`KEYCLOAK` (default in Docker)**:
   - Validates OAuth2/OIDC Bearer JWTs against Keycloak (`incert` realm).
   - Users: `admin` (`ROLE_ADMIN`), `operator` (`ROLE_ADMIN`, `ROLE_OPERATOR`), `auditor` (`ROLE_AUDITOR`, read-only).
2. **`SELF_MANAGED`**:
   - Standalone authentication without external Keycloak dependency.
3. **Machine & Break-Glass Access**:
   - API Key header: `X-API-KEY: incert-admin-secret-key` for `/api/v1/admin/**`.
   - HTTP Basic fallback: `admin:changeme`.

### Login TLS Activation / Deactivation
- Controlled via `security.tls.enabled` (`true` by default) and toggleable at runtime:
  - `GET /api/v1/auth/tls` -> returns `ACTIVE` or `DEACTIVATED`.
  - `POST /api/v1/auth/tls` (`{"enabled": true|false}`) -> toggles runtime TLS client-cert login acceptance.
- **When `ACTIVE`**: `POST /api/v1/auth/login` with `clientCert` grants `ROLE_ADMIN` (`authType: "TLS_CLIENT_CERT"`).
- **When `DEACTIVATED`**: `clientCert` login returns `400 Bad Request` (`"TLS authentication is currently deactivated in application configuration"`), while JWT/Basic/API-Key remain operational.

### RabbitMQ Transport Security
- **`RABBITMQ_TLS_ENABLED=true` (default)**: Mutual TLS (mTLS) on port `5671` with client keystore/truststore and `fail_if_no_peer_cert = true`.
- **`RABBITMQ_TLS_ENABLED=false`**: Plaintext AMQP fallback on port `5672` using `ocsp_amqp` / `changeme`.

