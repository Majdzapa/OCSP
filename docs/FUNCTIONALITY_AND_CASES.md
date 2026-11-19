# Incert OCSP Subsystem — Detailed Functional Cases & Background Jobs Specification

This document provides the complete functional specification of the **Incert OCSP Subsystem**, including:
1. **System Modules & Responsibilities**
2. **All Background Jobs, Scheduled Tasks, RabbitMQ Listeners & Lifecycle Hooks**
3. **Detailed Functional Cases & Edge-Case Matrix** across CA management, HSM key/CSR lifecycle, Multi-CA OCSP signing, RFC 6960 protocol handling, Outbox–Inbox messaging, zero-REST RabbitMQ reconciliation, and security.

---

## 1. System Modules & Responsibilities

| Module | Port | Schema / Storage | Core Responsibility |
|---|---|---|---|
| **`ocsp-responder`** | `8080` | MariaDB `ocsp` + SoftHSM2 token | RFC 6960 OCSP endpoint (`/ocsp`), PKCS#11 HSM signing, multi-CA signing certificate registry, RabbitMQ inbox consumer, zero-REST Outbox–Inbox reconciliation, dual-mode Spring Security |
| **`ocsp-console`** | `3000` | Browser `localStorage` | React 18 + Mantine v7 Admin UI (Dashboard, Signing Certificates, Revocations, Live Inbox Audit & Reconciliation, Cert Checker, Keycloak SSO / mTLS Login) |
| **`ocsp-client`** | `8082` | Stateless | Standalone RFC 6960 test client & web UI (`POST`/`GET`, Nonce generation & verification, response signature verification against CA PEM) |
| **`kms-simulator`** | `8090` | MariaDB `kms` | Root & Subordinate CA creation (`/kms/cas`), CSR & keygen certificate issuance, certificate revocation/hold/unrevoke (`/kms/certificates`), Transactional Outbox (`outbox_event`), RabbitMQ relay & manifest broadcaster |
| **`kms-console`** | `3001` | Stateless | React 18 + Mantine v7 KMS UI (Certificate Inventory, Certificate Authorities & CSR Issuance, RabbitMQ Outbox Monitor) |
| **`hsm` (SoftHSM2)** | N/A | Docker volumes `hsm-tokens`, `hsm-conf` | Dedicated PKCS#11 container initializing an empty token (`ocsp-signing`) where non-extractable RSA/EC private keys are generated on demand |
| **`rabbitmq`** | `5671` / `5672` / `15672` | Broker queues | AMQPS (strict mTLS on `5671`), AMQP plaintext fallback (`5672`), and Management UI (`15672`, credentials `ocsp_amqp` / `changeme`) |
| **`keycloak`** | `8081` | Realm `incert` | OAuth2 / OIDC Identity & Access Management (`admin`, `operator`, `auditor`) |
| **`mariadb`** | `3307` / `3308` | `ocsp` & `kms` | Persistent ACID relational storage managed by Flyway migrations |

---

## 2. All Background Jobs, Listeners & Event Hooks

Below is every background job, scheduled task, message listener, and transaction hook in the system.

### 2.1 Scheduled Background Jobs (`@Scheduled`)

| # | Job / Method | Service & Module | Schedule / Config Property | Exact Behavior & Failure Handling |
|---|---|---|---|---|
| **J1** | **Transactional Outbox Relay Job**<br>`OutboxRelayService.relay()` | `kms-simulator`<br>[`OutboxRelayService.java`](../../kms-simulator/src/main/java/com/company/incert/kms/service/OutboxRelayService.java) | `@Scheduled(fixedDelayString = "${kms.outbox.relay-delay-ms:500}")`<br>Runs every **500 ms** (and is also triggered immediately after REST mutations) | 1. Queries `kms.outbox_event` via `findBySentFalseOrderByCreatedAtAsc()`.<br>2. For each pending event, publishes the JSON payload to RabbitMQ exchange `incert.certificate.status` (routing key `incert.certificate.status.v1`) with AMQP `messageId = event.getEventId()`.<br>3. Marks `sent = true` and `sentAt = Instant.now()`.<br>4. **Ordering Guarantee**: If publishing fails, logs the error and **breaks out of the loop immediately** so subsequent events for the same certificate cannot overtake an unsent earlier event; retries on the next 500 ms tick. |
| **J2** | **KMS Outbox Manifest Broadcast Job**<br>`KmsReconciliationService.broadcastManifest()` | `kms-simulator`<br>[`KmsReconciliationService.java`](../../kms-simulator/src/main/java/com/company/incert/kms/service/KmsReconciliationService.java) | `@Scheduled(fixedDelayString = "${kms.reconciliation.manifest-delay-ms:3000}")`<br>Runs every **3000 ms (3 s)** | 1. Reads all certificates (`certificate` table) and all outbox rows (`outbox_event` table) in a read-only transaction.<br>2. Builds an `OutboxManifestEvent` containing `totalCertificates`, `totalOutboxEvents`, `sentOutboxEvents`, `pendingOutboxEvents`, all `outboxEventIds`, and a per-certificate digest `(serialNumberHex, status, revocationReason, sequence, latestEventId)`.<br>3. Publishes the manifest over RabbitMQ to exchange `incert.certificate.status` with routing key `incert.reconciliation.manifest.v1` (queue `ocsp.reconciliation.manifest`). |
| **J3** | **UI Live Inbox & Reconciliation Polling Job**<br>`useEffect` interval timer | `ocsp-console`<br>[`InboxAuditPage.tsx`](../ocsp-console/src/pages/InboxAuditPage.tsx) | `setInterval(..., 3000)`<br>Runs every **3000 ms (3 s)** while `Live Auto-Refresh (3s)` switch is enabled | Automatically calls `getInboxEvents()`, `getInboxStats()`, and `verifyReconciliation()` in silent mode every 3 seconds so new RabbitMQ inbox events, delivery tags, and Outbox–Inbox reconciliation state appear live without clicking Refresh. |

---

### 2.2 RabbitMQ Message Listeners (`@RabbitListener`)

| # | Listener / Method | Service & Queue | Headers Extracted | Exact Behavior & Transaction Boundary |
|---|---|---|---|---|
| **L1** | **Certificate Status Event Consumer**<br>`CertificateStatusListener.onMessage()` -> `CertificateStatusConsumerService.consume()` | `ocsp-responder`<br>Queue: `ocsp.certificate.status`<br>Routing key: `incert.certificate.status.v1`<br>DLQ: `ocsp.certificate.status.dlq` | `AmqpHeaders.MESSAGE_ID`<br>`AmqpHeaders.DELIVERY_TAG`<br>`AmqpHeaders.CONSUMER_QUEUE`<br>`AmqpHeaders.REDELIVERED` | Runs inside a single `@Transactional` method:<br>1. **Parse JSON**: Deserializes `CertificateStatusEvent`. If malformed JSON, calls `InboxFailureRecorder.recordFailure(messageId, ...)` in a separate `REQUIRES_NEW` transaction (preserving `event_id = messageId`) and throws `RuntimeException` so RabbitMQ routes the poison message to `ocsp.certificate.status.dlq`.<br>2. **Idempotency Check**: Looks up `inbox_event` by `eventId`. If present and not `FAILED`, updates `processing_status = DUPLICATE` with latest `deliveryTag`/`consumerQueue`/`redelivered` and returns.<br>3. **Apply Status**: Saves `inbox_event` as `RECEIVED`, calls `CertificateStatusService.applyStatusChange(event)`, and updates `inbox_event.processing_status` to `PROCESSED` (if applied) or `SKIPPED` (if stale/duplicate sequence).<br>4. **Processing Exception**: If any DB/domain error occurs, records a `FAILED` row via `InboxFailureRecorder` (`REQUIRES_NEW`) with the error message and AMQP `deliveryTag`, then rethrows to roll back the main transaction. |
| **L2** | **OCSP Outbox Manifest Listener**<br>`OutboxReconciliationService.onOutboxManifest()` | `ocsp-responder`<br>Queue: `ocsp.reconciliation.manifest`<br>Routing key: `incert.reconciliation.manifest.v1` | Payload: `OutboxManifestEvent` JSON | Deserializes the latest `OutboxManifestEvent` broadcast by `kms-simulator` and stores it atomically in `latestManifestRef` (`AtomicReference<OutboxManifestEvent>`) for zero-REST-call Outbox ↔ Inbox reconciliation. |
| **L3** | **KMS Reconciliation Command Listener**<br>`KmsReconciliationService.onReconciliationCommand()` | `kms-simulator`<br>Queue: `kms.reconciliation.request`<br>Routing key: `incert.reconciliation.request.v1` | Payload: `ReconciliationCommandMessage` JSON | Consumes commands sent by `ocsp-responder` over RabbitMQ:<br>- **`REQUEST_MANIFEST`**: Immediately broadcasts a fresh `OutboxManifestEvent`.<br>- **`REPLAY_EVENTS`**: Re-publishes any requested `missingEventIds` and/or the latest `OutboxEvent` for each requested `missingSerials` (or calls `revocationService.syncAll()` if both lists are empty), runs `outboxRelay.relay()`, and broadcasts an updated `OutboxManifestEvent`. |

---

### 2.3 JPA & Spring Transaction / Lifecycle Hooks

| # | Hook / Listener | Service & Trigger | Exact Behavior |
|---|---|---|---|
| **H1** | **JPA Certificate Entity Listener**<br>`CertificateStatusEntityListener` | `kms-simulator`<br>`@PostPersist` & `@PostUpdate` on `Certificate` | Automatically snapshots `(loadedStatus, loadedSequence)` and publishes a `CertificateStatusEvent` via Spring's `ApplicationEventPublisher` whenever a `Certificate` is created (`@PostPersist`) or its status/sequence changes (`@PostUpdate`). |
| **H2** | **Transactional Outbox Event Writer**<br>`CertificateOutboxEventListener.onCertificateStatusChanged()` | `kms-simulator`<br>`@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)` + `@Transactional(propagation = Propagation.REQUIRES_NEW)` | Fires **only after** the `Certificate` DB transaction commits. Persists an `OutboxEvent` row (`event_id`, `topic = "incert.certificate.status.v1"`, `event_key = issuerKeyHash + ":" + serialHex`, `payload`, `sent = false`). |
| **H3** | **HSM Signer Post-Commit Synchronizer**<br>`SigningCertificateService.onSigningConfigurationChanged()` | `ocsp-responder`<br>`@TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)` | Fires **only after** a signing certificate addition, activation, deactivation, or deletion commits in MariaDB. Updates the active in-memory PKCS#11 signer (`ocspSigner.updateActiveCertificate(...)`) and refreshes the multi-CA signer registry (`ocspSigner.syncRegisteredSigners(...)`), ensuring a DB rollback can never leave the HSM signer out of sync with the database. |
| **H4** | **Responder Startup Signer Loader**<br>`SigningCertificateService.initDefaultCertificate()` | `ocsp-responder`<br>`@EventListener(ApplicationReadyEvent.class)` | On startup, loads all active signing certificates from `ocsp.signing_certificates` and synchronizes them with the PKCS#11 HSM signer. **Does not create any default certificate**; if the table is empty, logs that `/ocsp` will respond with `TRY_LATER` until a signing certificate is configured. |

---

## 3. Detailed Functional Cases

### Section A: Certificate Authority (CA) Creation & Certificate Issuance (`kms-simulator`)

> **Zero Static Data Principle**: `kms-simulator` starts with `0` CAs and `0` certificates. Every CA and certificate is created explicitly by the user.

#### Case A1: Create a Self-Signed Root CA
- **Endpoint / UI**: `POST /kms/cas` (KMS Console -> **Certificate Authorities -> Create CA** with **Issuing CA** empty)
- **Inputs**: `name`, `subjectDn` (e.g. `CN=Incert Root CA,O=Incert,C=CH`), `keyAlgorithm` (`RSA` or `EC`), `keySize` (`2048`/`3072`/`4096` for RSA; `256`/`384` for EC), optional `validityDays` (defaults to `3650` days).
- **Process**:
  1. Validates unique `name`, valid X.500 `subjectDn`, and supported `keyAlgorithm`/`keySize`.
  2. Generates the keypair via BouncyCastle and builds a self-signed X.509v3 CA certificate (`BasicConstraints: CA=TRUE`, `KeyUsage: keyCertSign | cRLSign`, `SubjectKeyIdentifier`, `AuthorityKeyIdentifier`).
  3. Computes RFC 6960 SHA-1 `issuerNameHashHex` (SHA-1 of DER-encoded Subject DN) and `issuerKeyHashHex` (SHA-1 of SubjectPublicKeyInfo raw key bytes).
  4. Persists `CertificateAuthority` (`parent_id = NULL`).
- **Expected Result**: Returns `201 Created` with `CaDto` (`root: true`, `certificatePem`, hashes, validity). Private key is stored internally and never returned in `CaDto`.

#### Case A2: Create a Subordinate / Intermediate CA
- **Endpoint / UI**: `POST /kms/cas` with `parentCaId` set to an existing CA ID.
- **Process**:
  1. Loads the parent CA's certificate and private key.
  2. Caps default validity (`1825` days) so `notAfter` never exceeds the parent CA's `notAfter` (rejects with `400 Bad Request` if an explicit `validityDays` exceeds the parent CA's expiry).
  3. Signs the subordinate CA certificate using the **parent CA's** private key and signature algorithm, while storing the subordinate CA's **own** signature algorithm (derived from its own RSA/EC key) for certificates it will issue later.
- **Expected Result**: Returns `201 Created` with `CaDto` (`root: false`, `parentId`). Calling `GET /kms/cas/{id}/certificate?chain=true` returns the full PEM chain (Subordinate CA PEM + Root CA PEM).

#### Case A3: Issue an OCSP Signing Certificate from an HSM CSR (`OCSP_SIGNING` Profile)
- **Endpoint / UI**: `POST /kms/cas/{caId}/certificates` with `csrPem` and `profile = "OCSP_SIGNING"`.
- **Process**:
  1. Parses the PKCS#10 `csrPem` and **verifies its cryptographic signature (proof-of-possession)** against the CSR's public key.
  2. Extracts the Subject DN and Public Key from the CSR.
  3. Issues an X.509v3 certificate signed by `caId` with:
     - `BasicConstraints`: critical, `CA=FALSE`
     - `KeyUsage`: critical, `digitalSignature`
     - `ExtendedKeyUsage`: critical, `id-kp-OCSPSigning` (`1.3.6.1.5.5.7.3.9`)
     - `id-pkix-ocsp-nocheck` (`1.3.6.1.5.5.7.48.1.5`): `DERNull` (RFC 6960 §4.2.2.2.1 so clients don't attempt recursive OCSP checks on the responder's own certificate)
  4. Saves the certificate in `kms.certificate` with `status = GOOD`, `sequence = 0`, `ca_id = caId`.
  5. Triggers `CertificateStatusEntityListener` -> `CertificateOutboxEventListener` -> `OutboxRelayService.relay()` -> publishes `CertificateStatusChanged` to RabbitMQ.
- **Expected Result**: Returns `201 Created` with `certificatePem`, `chainPem`, `serialNumberHex`, and `privateKeyPem = null` (since the private key never left the HSM).

#### Case A4: Issue an End-Entity Certificate (`TLS_SERVER`, `TLS_CLIENT`, or `GENERIC`)
- **Endpoint / UI**: `POST /kms/cas/{caId}/certificates`
- **Two Modes**:
  - **Mode 1 — From CSR (`csrPem` provided)**: Uses CSR's public key and Subject DN, copies any `SubjectAlternativeName` extension from the CSR, returns `privateKeyPem = null`.
  - **Mode 2 — KMS-Generated Key (`subjectDn` provided without `csrPem`)**: KMS generates the RSA/EC keypair, signs the certificate, and returns `privateKeyPem` **once** in the response (never stored in the DB).
- **Profile Extensions**:
  - `TLS_SERVER`: `KeyUsage: digitalSignature | keyEncipherment` (RSA) or `digitalSignature` (EC), `EKU: serverAuth`, `AIA: OCSP URI`.
  - `TLS_CLIENT`: `KeyUsage: digitalSignature`, `EKU: clientAuth`, `AIA: OCSP URI`.
  - `GENERIC`: `KeyUsage: digitalSignature`, `AIA: OCSP URI`.

#### Case A5: CA & Issuance Validation / Rejection Cases
| Invalid Input Case | Expected Response |
|---|---|
| Duplicate CA `name` | `400 Bad Request`: `"A certificate authority named '...' already exists"` |
| Malformed X.500 `subjectDn` | `400 Bad Request`: `"Invalid subjectDn ..."` |
| Unsupported key size (e.g. RSA `1024` or EC `521`) | `400 Bad Request`: `"RSA keySize must be 2048, 3072 or 4096"` / `"EC keySize must be 256 or 384"` |
| CSR with invalid signature (forged proof-of-possession) | `400 Bad Request`: `"CSR signature is invalid (proof of possession failed)"` |
| Neither `csrPem` nor `subjectDn` provided | `400 Bad Request`: `"Provide either csrPem, or subjectDn..."` |
| Requested `validityDays` exceeds issuing CA's `notAfter` | `400 Bad Request`: `"Requested validity exceeds the issuing CA validity..."` |
| Unknown `caId` | `404 Not Found`: `"Certificate authority not found: ..."` |

---

### Section B: HSM Key Management & Multi-CA Signing Certificates (`ocsp-responder` & `hsm`)

#### Case B1: Fresh Startup Before Any Signing Certificate Is Configured
- **State**: `ocsp-hsm` initializes an empty SoftHSM2 token (`ocsp-signing`). `ocsp.signing_certificates` has `0` rows.
- **Behavior**:
  - `ocsp-responder` starts and is `Healthy`.
  - Any live OCSP request to `POST /ocsp` or `GET /ocsp/{b64}` throws `SignerNotConfiguredException`, increments metric `ocsp.request.error{reason="no_signer"}`, and returns a valid DER-encoded RFC 6960 **`TRY_LATER` (`status = 3`)** response.

#### Case B2: Generate a New Keypair & CSR in the HSM
- **Endpoint / UI**: `POST /api/v1/admin/signing-certificates/csr` (`reuseExistingKey = false`)
- **Process**:
  1. Verifies `keyLabel` does not already exist in the PKCS#11 `KeyStore` (if it does and `reuseExistingKey = false`, rejects with `"Key label '...' already exists in HSM token. Choose a new label or enable reuse."`).
  2. Generates a non-extractable RSA (`2048`/`3072`/`4096`) or EC (`secp256r1`/`secp384r1`) keypair inside the SoftHSM2 token via `SunPKCS11`.
  3. Signs a PKCS#10 CSR inside the HSM using `SHA256withRSA` or `SHA256withECDSA`.
- **Expected Result**: Returns `GenerateCsrResponse` with `keyLabel`, `subjectDn`, `keyAlgorithm`, and `csrPem`.

#### Case B3: Generate a Renewal CSR Reusing an Existing HSM Keypair
- **Endpoint / UI**: `POST /api/v1/admin/signing-certificates/csr` (`reuseExistingKey = true`)
- **Process**: Loads the existing `PrivateKey` and `PublicKey` for `keyLabel` from the SoftHSM2 token without generating a new keypair, and signs a fresh PKCS#10 CSR.

#### Case B4: Import & Activate a CA-Signed OCSP Signing Certificate
- **Endpoint / UI**: `POST /api/v1/admin/signing-certificates` (`alias`, `keyLabel`, `certificatePem`, `signatureAlgorithm`, `activateImmediately`)
- **Process**:
  1. Checks unique `alias` and verifies the certificate is not expired (`Instant.now().isAfter(notAfter)`).
  2. Validates `signatureAlgorithm` against the certificate's key type (`RSA` or `EC`) using the `SigningAlgorithm` enum (`SHA256withRSA`, `SHA384withRSA`, `SHA512withRSA`, `SHA256withRSAandMGF1`, `SHA256withECDSA`, `SHA384withECDSA`, `SHA512withECDSA`).
  3. Calls `ocspSigner.importCertificateToToken(keyLabel, holder)`:
     - Verifies `keyLabel` exists in the HSM token.
     - **Public Key Match Verification**: Compares the imported certificate's public key bytes against the HSM keypair's public key bytes. If they differ, throws `IllegalArgumentException("Imported certificate public key does not match the HSM private key '...'")`.
     - Binds the CA-signed certificate to `keyLabel` in the PKCS#11 `KeyStore`.
  4. Saves the row in `ocsp.signing_certificates` (and if `activateImmediately = true`, marks `active = true`, `activatedAt = Instant.now()`).
  5. After DB commit (`@TransactionalEventListener(AFTER_COMMIT)`), updates the in-memory PKCS#11 signer and multi-CA registry.

#### Case B5: Multiple Simultaneously Active Signing Certificates (Multi-CA Selection)
- **Scenario**: Active Certificate 1 is issued by **CA 1** (or Key 1) and Active Certificate 2 is issued by **CA 2** (or Key 2, even with the same Subject DN but different public key / `AuthorityKeyIdentifier`). Both have `active = true`.
- **Per-Request Selection (`Pkcs11OcspSigner.selectSigner(CertID)`)**:
  1. Extracts `reqIssuerNameHash`, `reqIssuerKeyHash`, and `hashAlgOid` from the incoming OCSP request's `CertID`.
  2. Computes each active, non-expired signing certificate's issuer DN digest (`md.digest(entry.issuerEncoded())`) and compares it with `reqIssuerNameHash`.
  3. When using SHA-1 (`idSHA1`) and the signing certificate has an `AuthorityKeyIdentifier` (`keyIdentifier`), also compares `entry.authorityKeyId()` with `reqIssuerKeyHash`:
     - Exact match on both **Issuer DN hash AND Authority Key Identifier (`issuerKeyHash`)** gets the highest score (`score = 3 + preferred`).
     - If `AuthorityKeyIdentifier` differs from `reqIssuerKeyHash` (two CAs sharing the same Subject DN but different public keys), that entry is skipped so the certificate issued by the matching CA public key is selected.
  4. Signs the `BasicOCSPResp` with the selected certificate's HSM private key and embeds its certificate chain in the OCSP response.

#### Case B6: Signing Certificate Edge & Rejection Cases
| Case | Expected Behavior |
|---|---|
| Import cert whose public key doesn't match HSM `keyLabel` | Rejected (`400 Bad Request`: `"Imported certificate public key does not match the HSM private key '...'"`) |
| Import RSA cert with ECDSA `signatureAlgorithm` (or vice-versa) | Rejected (`400 Bad Request`: `"Unsupported or incompatible RSA/EC signature algorithm..."`) |
| Activate an expired certificate | Rejected (`400/409`: `"Cannot activate an expired certificate"`) |
| Activate cert whose `keyLabel` is missing from HSM token | Rejected (`400/409`: `"Cannot activate certificate '...': HSM key '...' not found in token"`) |
| Deactivate the last remaining active signing certificate | Rejected (`400/409`: `"Cannot deactivate the last remaining active signing certificate"`) |
| Deactivate one active certificate when others remain active | Allowed; the most recently activated remaining certificate becomes the fallback primary signer after DB commit |
| Delete an active signing certificate | Rejected (`400/409`: `"Cannot delete the currently active signing certificate. Please activate another certificate first."`) |

---

### Section C: RFC 6960 Live OCSP Protocol Cases (`ocsp-responder` & `ocsp-client`)

| Case | Input / Trigger | Responder Behavior |
|---|---|---|
| **C1: `GOOD` Certificate** | `POST /ocsp` or `GET /ocsp/{b64}` for a serial with `status = GOOD` in `ocsp.revocation_status` | Selects matching CA signing cert, returns `OCSPRespBuilder.SUCCESSFUL` (`0`) with `SingleResp` status `CertificateStatus.GOOD` (`null`), `thisUpdate`, `nextUpdate`, signed via PKCS#11 HSM. |
| **C2: `REVOKED` Certificate** | Request for a serial with `status = REVOKED` (including `CERTIFICATE_HOLD`) | Returns `OCSPRespBuilder.SUCCESSFUL` (`0`) with `RevokedStatus(revocationTime, reasonCode)`. |
| **C3: `UNKNOWN` Certificate** | Request for a serial not present in `ocsp.revocation_status` | `findByCertId` checks `(issuer_name_hash, issuer_key_hash, serial_number)` then falls back to `findBySerialNumber(serial_number)`. When neither matches, returns `UnknownStatus`. |
| **C4: Nonce Echo (`id-pkix-ocsp-nonce`)** | Request includes a Nonce extension (`1..32` octets per RFC 8954) | Echoes the exact request nonce extension in `BasicOCSPResp` and increments `ocsp.request.nonce{present="true"}`. If nonce exceeds 32 octets, returns `MALFORMED_REQUEST`. |
| **C5: Malformed Request** | Empty body, body `> 10 KB`, `> 10` CertIDs, invalid ASN.1 DER, or invalid Base64 in `GET /ocsp/{b64}` | Returns `OCSPRespBuilder.MALFORMED_REQUEST` (`1`) and increments `ocsp.request.error{reason="malformed"}`. |
| **C6: No Active Signer Configured** | Request arrives before any signing certificate is activated | Catches `SignerNotConfiguredException`, returns `OCSPRespBuilder.TRY_LATER` (`3`), and increments `ocsp.request.error{reason="no_signer"}`. |

---

### Section D: Certificate Revocation, Hold & Reinstatement (`kms-simulator`)

| Case | Endpoint | State Transition & Sequence Behavior |
|---|---|---|
| **D1: Permanent Revocation** | `POST /kms/certificates/{serial}/revoke?reason=KEY_COMPROMISE` | `GOOD -> REVOKED`, sets `revocationTime = Instant.now()`, `revocationReason = KEY_COMPROMISE`, increments `sequence = sequence + 1`. Emits `OutboxEvent` and relays immediately to RabbitMQ. |
| **D2: Temporary Suspension (`CERTIFICATE_HOLD`)** | `POST /kms/certificates/{serial}/revoke?reason=CERTIFICATE_HOLD` | `GOOD -> REVOKED` with `revocationReason = CERTIFICATE_HOLD`, increments `sequence = sequence + 1`, relays to RabbitMQ. |
| **D3: Reinstate Held Certificate (`unrevoke`)** | `POST /kms/certificates/{serial}/unrevoke` | Allowed **only** if current `revocationReason == CERTIFICATE_HOLD`. Transitions `REVOKED -> GOOD`, clears `revocationTime` and `revocationReason`, increments `sequence = sequence + 1`, relays to RabbitMQ. |
| **D4: Reject Unrevoke on Permanently Revoked Cert** | `POST /kms/certificates/{serial}/unrevoke` on `KEY_COMPROMISE` | Rejected with `400 Bad Request` (`"Can only unrevoke CERTIFICATE_HOLD, current reason: KEY_COMPROMISE"`). |

---

### Section E: Outbox–Inbox Messaging & Failure Traceability Cases

| Case | Trigger | `ocsp.inbox_event` & Broker Result |
|---|---|---|
| **E1: Normal Event Delivery** | Valid `CertificateStatusChanged` with `sequence > storedSequence` | Row saved with `event_id`, `processing_status = PROCESSED`, `delivery_tag`, `consumer_queue`, `redelivered = false`; `ocsp.revocation_status` updated in the same transaction. |
| **E2: Duplicate Event ID Delivery** | Same `event_id` redelivered when existing row is `PROCESSED` / `SKIPPED` | Existing row updated to `processing_status = DUPLICATE` with latest `delivery_tag` and `redelivered` flag; `revocation_status` untouched. |
| **E3: Out-of-Order / Stale Sequence** | New `event_id` arrives with `event.sequence < revocation_status.sequence` | `CertificateStatusService.applyStatusChange` returns `false`; `inbox_event` recorded with `processing_status = SKIPPED`; newer state in `revocation_status` is preserved. |
| **E4: Malformed JSON / Poison Message** | Invalid JSON payload published to `ocsp.certificate.status` | Main `@Transactional` rolls back (routing message to `ocsp.certificate.status.dlq`), while `InboxFailureRecorder.recordFailure` (`Propagation.REQUIRES_NEW`) commits a `FAILED` row in `ocsp.inbox_event` using `AmqpHeaders.MESSAGE_ID` as `event_id` (preserving the exact link to `kms.outbox_event.event_id`), plus `delivery_tag`, `consumer_queue`, `redelivered`, and `error_message`. |
| **E5: Retry of Previously `FAILED` Event** | An event whose `event_id` is currently `FAILED` in `ocsp.inbox_event` is replayed | The idempotency check explicitly allows reprocessing when prior status is `FAILED`; on success, the row transitions from `FAILED` to `PROCESSED` and clears `error_message`. |

---

### Section F: Purely RabbitMQ-Based Outbox ↔ Inbox Reconciliation & Replay (Zero REST Calls)

| Case | Scenario | Detection (`GET /api/v1/admin/reconciliation/verify`) | Self-Healing (`POST /api/v1/admin/reconciliation/replay`) |
|---|---|---|---|
| **F1: 100% Synchronized** | All `kms.outbox_event` IDs are `PROCESSED`/`SKIPPED`/`DUPLICATE` in `ocsp.inbox_event` and all KMS certificates match `ocsp.revocation_status` | `synchronized: true`, `missingInInboxCount: 0`, `failedInInboxCount: 0`, `missingCount: 0`, `mismatchCount: 0` | Publishes `REPLAY_EVENTS` over RabbitMQ; KMS re-verifies and broadcasts fresh manifest. |
| **F2: Event Lost Before Reaching Inbox (`MISSING_IN_INBOX`)** | `event_id` exists in KMS `OutboxManifestEvent.outboxEventIds`, but is absent from `ocsp.inbox_event` | `synchronized: false`, `missingInInboxEventIds: ["<event_id>"]` | Publishes `REPLAY_EVENTS` with `missingEventIds: ["<event_id>"]` to `kms.reconciliation.request`; KMS re-publishes that exact `OutboxEvent` over RabbitMQ. |
| **F3: Event Failed in Inbox (`FAILED_IN_INBOX`)** | `event_id` is in `ocsp.inbox_event` with `processing_status = FAILED` | `synchronized: false`, `failedInInboxEventIds: ["<event_id>"]` | Publishes `REPLAY_EVENTS` with `missingEventIds: ["<event_id>"]`; KMS re-publishes the event, and `ocsp-responder` reprocesses it from `FAILED` to `PROCESSED`. |
| **F4: Missing or Stale Row in `revocation_status`** | Certificate serial in KMS manifest is missing from `ocsp.revocation_status` or has `responder.sequence < kms.sequence` | `synchronized: false`, listed in `missingSerials` or `statusMismatches` | Publishes `REPLAY_EVENTS` with `missingSerials: ["<serialHex>"]`; KMS re-publishes the latest `OutboxEvent` for that serial over RabbitMQ. |
