# Incert OCSP Subsystem — Architectural Floorplan & Visual Workflows (v5.0)

This document maps out the complete **System Floorplan** (zones, rooms, ports, data stores, cryptographic boundaries, message queues, and background jobs) along with visual flowcharts for every functional case.

---

## 1. Master System Floorplan (Zones, Ports & Boundaries)

```mermaid
flowchart TB
    subgraph ZONE_EXTERNAL["Zone 1: External Relying Parties & Operators"]
        RP["Relying Parties\n(Browsers, TLS Gateways, mTLS Services)"]
        TESTER["OCSP Client Tester\n(http://localhost:8082)"]
        OCSP_ADMIN["OCSP Security Admin\n(http://localhost:3002)"]
        KMS_ADMIN["PKI / CA Operator\n(http://localhost:3001)"]
    end

    subgraph ZONE_UI["Zone 2: Presentation & Admin Consoles"]
        subgraph ROOM_OCSP_UI["ocsp-console (:3000 - React 18 / Mantine v7)"]
            UI_DASH["/dashboard\nLive Telemetry & Health"]
            UI_INBOX["/inbox\nLive 3s Auto-Refresh Audit\n& RabbitMQ Replay"]
            UI_REV["/revocations\nRevocation Feed"]
            UI_SIGN["/signing-cert\nMulti-CA Signers & HSM CSR"]
            UI_VALID["/signing-validity\nDaily Validity Monitor,\n3-Day Alert & Renewal CSR"]
            UI_CHECK["/cert-checker\nLive RFC 6960 Tester\n(with Issuer CA PEM)"]
        end

        subgraph ROOM_KMS_UI["kms-console (:3001 - React 18 / Mantine v7)"]
            KUI_CAS["/cas\nCreate Root & Sub CAs\nIssue Certs from CSR"]
            KUI_INV["/\nCertificate Inventory\nRevoke / Hold / Unrevoke"]
            KUI_OUT["/outbox\nTransactional Outbox Monitor"]
        end
    end

    subgraph ZONE_IAM["Zone 3: Identity & Access Management"]
        KC["ocsp-keycloak (:8081)\nRealm: incert\nGroups: /ocsp-administrators,\n/ocsp-operators, /ocsp-auditors"]
    end

    subgraph ZONE_KMS["Zone 4: KMS & Certificate Authority Engine (:8090 / :3308)"]
        KMS_CA_SVC["CertificateAuthorityService\n• Create Root / Subordinate CA\n• Verify CSR Proof-of-Possession\n• Issue OCSP_SIGNING, TLS_SERVER,\n  TLS_CLIENT, GENERIC Certs"]
        KMS_REV_SVC["RevocationService\n• Revoke / Hold / Unrevoke\n• Monotonic Sequence Counter"]
        KMS_HOOKS["JPA @PostPersist/@PostUpdate\n-> @TransactionalEventListener(AFTER_COMMIT)\nCertificateOutboxEventListener"]
        KMS_JOB_RELAY["Job J1: OutboxRelayService\n@Scheduled(500ms)\nStrict Ordering Relay"]
        KMS_JOB_MAN["Job J2: KmsReconciliationService\n@Scheduled(3000ms) Manifest Broadcast\n& @RabbitListener Replay Handler"]
        KMS_DB[("kms-mariadb (:3308)\nSchema: kms\n• certificate_authority\n• certificate\n• outbox_event")]

        KMS_CA_SVC --> KMS_DB
        KMS_REV_SVC --> KMS_DB
        KMS_CA_SVC --> KMS_HOOKS
        KMS_REV_SVC --> KMS_HOOKS
        KMS_HOOKS --> KMS_DB
        KMS_JOB_RELAY --> KMS_DB
        KMS_JOB_MAN --> KMS_DB
    end

    subgraph ZONE_BROKER["Zone 5: RabbitMQ Event & Reconciliation Bus (:5671 mTLS / :5672 / :15672)"]
        EX["Direct Exchange: incert.certificate.status"]
        Q_STATUS["Queue: ocsp.certificate.status\nKey: incert.certificate.status.v1\nHeader: MESSAGE_ID = event_id"]
        Q_DLQ["DLX/DLQ: ocsp.certificate.status.dlq\n(Poison / Failed Payloads)"]
        Q_MAN["Queue: ocsp.reconciliation.manifest\nKey: incert.reconciliation.manifest.v1\n(OutboxManifestEvent)"]
        Q_REQ["Queue: kms.reconciliation.request\nKey: incert.reconciliation.request.v1\n(REQUEST_MANIFEST / REPLAY_EVENTS)"]

        EX --> Q_STATUS
        Q_STATUS -.->|Rollback / NACK| Q_DLQ
        EX --> Q_MAN
        EX --> Q_REQ
    end

    subgraph ZONE_RESPONDER["Zone 6: OCSP Responder Core (:8080 / :3307)"]
        OCSP_SEC["Security Gate\nKEYCLOAK JWT / SELF_MANAGED\nX-API-KEY / Basic / Runtime mTLS Toggle"]
        OCSP_PROTO["OcspResponderService\n• RFC 6960 POST & GET\n• Nonce Echo (1..32B)\n• Strict CertID Lookup\n• TRY_LATER if No Signer"]
        OCSP_SIGN_SVC["SigningCertificateService\n• HSM CSR Generation\n• Public Key Match Check\n• @TransactionalEventListener(AFTER_COMMIT)"]
        OCSP_JOB_VAL["Job J4: SigningCertificateValidityService\n@Scheduled(0 0 0 * * *)\nDaily Check, 3-Day Alert & Renewal CSR"]
        OCSP_CONS["Listener L1: CertificateStatusListener\n-> CertificateStatusConsumerService\n+ InboxFailureRecorder (REQUIRES_NEW)"]
        OCSP_RECON["Listener L2: OutboxReconciliationService\nZero-REST Outbox vs Inbox Diff\n& RabbitMQ Replay Publisher"]
        OCSP_DB[("ocsp-mariadb (:3307)\nSchema: ocsp\n• revocation_status\n• signing_certificates\n• inbox_event")]

        OCSP_PROTO --> OCSP_DB
        OCSP_SIGN_SVC --> OCSP_DB
        OCSP_JOB_VAL --> OCSP_DB
        OCSP_CONS --> OCSP_DB
        OCSP_RECON --> OCSP_DB
    end

    subgraph ZONE_HSM["Zone 7: Cryptographic HSM Boundary (ocsp-hsm)"]
        HSM_TOKEN["SoftHSM2 Token: ocsp-signing\nShared Volumes: hsm-tokens, hsm-conf\n• Empty on Init (Zero Static Keys)\n• On-Demand Non-Extractable RSA/EC Keys\n• Multi-CA Signer Selection by CertID"]
    end

    subgraph ZONE_CLIENT["Zone 8: Standalone OCSP Verifier (ocsp-client :8082)"]
        CLIENT_ENGINE["OcspClientService\nBuilds CertID from Issuer CA PEM,\nVerifies OCSP Signature, EKU & Nonce"]
    end

    RP --> OCSP_PROTO
    TESTER --> CLIENT_ENGINE --> OCSP_PROTO
    OCSP_ADMIN --> ROOM_OCSP_UI
    KMS_ADMIN --> ROOM_KMS_UI
    ROOM_OCSP_UI --> OCSP_SEC
    ROOM_OCSP_UI --> CLIENT_ENGINE
    ROOM_OCSP_UI --> KC
    OCSP_SEC --> KC
    ROOM_KMS_UI --> KMS_CA_SVC
    ROOM_KMS_UI --> KMS_REV_SVC
    KMS_JOB_RELAY -->|mTLS 5671| EX
    KMS_JOB_MAN -->|mTLS 5671| EX
    Q_STATUS --> OCSP_CONS
    Q_MAN --> OCSP_RECON
    OCSP_RECON -->|mTLS 5671| EX
    Q_REQ --> KMS_JOB_MAN
    OCSP_PROTO --> HSM_TOKEN
    OCSP_SIGN_SVC --> HSM_TOKEN
```

---

## 2. Floorplan of All Background Jobs & Event Listeners

```mermaid
flowchart LR
    subgraph KMS_JOBS["KMS Simulator Jobs & Hooks"]
        H1["Hook H1: CertificateStatusEntityListener\n(@PostPersist / @PostUpdate on Certificate)"]
        H2["Hook H2: CertificateOutboxEventListener\n(@TransactionalEventListener AFTER_COMMIT\n+ Propagation.REQUIRES_NEW)"]
        J1["Job J1: OutboxRelayService.relay()\n(@Scheduled every 500ms)\nSets AMQP messageId = event_id"]
        J2["Job J2: KmsReconciliationService.broadcastManifest()\n(@Scheduled every 3000ms)\nPublishes OutboxManifestEvent"]
        L3["Listener L3: KmsReconciliationService.onReconciliationCommand()\n(@RabbitListener kms.reconciliation.request)\nReplays missing/failed events & synthesizes missing outbox rows"]

        H1 --> H2 --> J1
    end

    subgraph BROKER_QUEUES["RabbitMQ Queues"]
        Q1[("ocsp.certificate.status")]
        Q2[("ocsp.reconciliation.manifest")]
        Q3[("kms.reconciliation.request")]
        DLQ[("ocsp.certificate.status.dlq")]
    end

    subgraph OCSP_JOBS["OCSP Responder & Console Jobs & Listeners"]
        L1["Listener L1: CertificateStatusListener\n(@RabbitListener ocsp.certificate.status)\nExtracts MESSAGE_ID, DELIVERY_TAG, QUEUE, REDELIVERED"]
        FAIL["InboxFailureRecorder.recordFailure()\n(Propagation.REQUIRES_NEW)\nPersists FAILED row with event_id = MESSAGE_ID"]
        L2["Listener L2: OutboxReconciliationService.onOutboxManifest()\n(@RabbitListener ocsp.reconciliation.manifest)\nCaches KMS Outbox Manifest & computes diff"]
        H3["Hook H3: SigningCertificateService.onSigningConfigurationChanged()\n(@TransactionalEventListener AFTER_COMMIT)\nSyncs active signers to PKCS#11 HSM only after DB commit"]
        J4["Job J4: SigningCertificateValidityService.runDailyValidityCheck()\n(@Scheduled cron '0 0 0 * * *' daily at 00:00)\nChecks expiry & raises 3-day alerts"]
        J3["Job J3: InboxAuditPage Live Auto-Refresh\n(setInterval every 3000ms)\nPolls /inbox, /inbox/stats & /reconciliation/verify"]
    end

    J1 --> Q1 --> L1
    L1 -.->|Exception / Rollback| FAIL
    L1 -.->|NACK| DLQ
    J2 --> Q2 --> L2
    L2 -->|REPLAY_EVENTS / REQUEST_MANIFEST| Q3 --> L3
    L3 --> J1
    J3 --> L2
```

---

## 3. Functional Case Floorplan: End-to-End Decision Flows

### 3.1 CA Creation, HSM Key/CSR Generation, Signing Cert Activation & Renewal Flow

```mermaid
flowchart TD
    START(["Fresh Deployment\n(Zero CAs, Zero Keys, Zero Signing Certs)"])
    TRY_LATER["Live OCSP Requests to /ocsp\nReturn RFC 6960 TRY_LATER (3)"]
    CREATE_CA["1. KMS Console (:3001/cas)\nPOST /kms/cas\nCreate Root or Subordinate CA (RSA / EC)"]
    GEN_CSR["2. OCSP Console (:3000/signing-cert)\nPOST /api/v1/admin/signing-certificates/csr\nGenerate Non-Extractable Keypair in SoftHSM2 & Sign PKCS#10 CSR"]
    ISSUE_SIGN["3. KMS Console (:3001/cas)\nPOST /kms/cas/{caId}/certificates\nVerify CSR Signature & Issue Cert (Profile: OCSP_SIGNING)"]
    IMPORT_SIGN["4. OCSP Console (:3000/signing-cert)\nPOST /api/v1/admin/signing-certificates\nVerify Public Key Matches HSM Key & Activate"]
    AFTER_COMMIT["Hook H3: @TransactionalEventListener(AFTER_COMMIT)\nUpdates In-Memory Pkcs11OcspSigner & Multi-CA Registry"]
    DAILY_JOB["Job J4: Daily Validity Check (00:00 UTC)\n& /signing-validity Screen"]
    CHECK_3D{"Days Until Expiry <= 3?"}
    HEALTHY["Status: HEALTHY\n(> 3 Days Remaining)"]
    ALERT_3D["Status: EXPIRING_SOON (<= 3 Days) or EXPIRED\nCritical Alert Banner & [SIGNING-CERT-ALERT] Log"]
    RENEW_REQ["Click 'Request to Renew'\nPOST /api/v1/admin/signing-certificates/{id}/renew-request\nGenerates Renewal CSR (Reusing HSM Key or New Key Label)"]

    START --> TRY_LATER
    START --> CREATE_CA --> GEN_CSR --> ISSUE_SIGN --> IMPORT_SIGN --> AFTER_COMMIT --> DAILY_JOB
    DAILY_JOB --> CHECK_3D
    CHECK_3D -->|No| HEALTHY
    CHECK_3D -->|Yes| ALERT_3D --> RENEW_REQ --> ISSUE_SIGN
```

### 3.2 Live RFC 6960 OCSP Request Decision Floorplan

```mermaid
flowchart TD
    REQ(["Incoming OCSP Request\nPOST /ocsp or GET /ocsp/{base64url}"])
    PARSE{"Valid ASN.1 DER,\n<= 10 CertIDs,\nNonce 1..32B?"}
    MALFORMED["Return OCSPResp:\nMALFORMED_REQUEST (1)"]
    HAS_SIGNER{"At least 1 Active\nNon-Expired Signer?"}
    TRY_LATER["Return OCSPResp:\nTRY_LATER (3)"]
    SELECT_SIGNER["Multi-CA Signer Selection:\nMatch CertID issuerNameHash +\nAuthorityKeyIdentifier (issuerKeyHash)"]
    DB_LOOKUP{"Strict CertID Match in\nocsp.revocation_status?\n(issuer_name_hash,\nissuer_key_hash,\nserial_number)"}
    UNKNOWN["SingleResp: UNKNOWN\n(Serial not found OR\nWrong Issuer CA PEM)"]
    STATUS_CHECK{"Row Status?"}
    GOOD["SingleResp: GOOD"]
    REVOKED["SingleResp: REVOKED\n(with revocationTime & reason)"]
    SIGN_HSM["Echo Nonce (if present) &\nSign BasicOCSPResp in SoftHSM2 (PKCS#11)"]

    REQ --> PARSE
    PARSE -->|Invalid| MALFORMED
    PARSE -->|Valid| HAS_SIGNER
    HAS_SIGNER -->|No| TRY_LATER
    HAS_SIGNER -->|Yes| SELECT_SIGNER --> DB_LOOKUP
    DB_LOOKUP -->|Not Found| UNKNOWN --> SIGN_HSM
    DB_LOOKUP -->|Found| STATUS_CHECK
    STATUS_CHECK -->|GOOD| GOOD --> SIGN_HSM
    STATUS_CHECK -->|REVOKED| REVOKED --> SIGN_HSM
```

### 3.3 Zero-REST Outbox ↔ Inbox Reconciliation & Self-Healing Replay Floorplan

```mermaid
flowchart TD
    KMS_OUTBOX[("kms.outbox_event\n& kms.certificate")]
    MANIFEST["Job J2 (Every 3s):\nBroadcast OutboxManifestEvent\nto ocsp.reconciliation.manifest"]
    VERIFY["OCSP Responder:\nGET /api/v1/admin/reconciliation/verify\nCompares Manifest vs ocsp.inbox_event & revocation_status"]
    SYNC_CHECK{"Any Missing, Failed,\nor Mismatched Events?"}
    IN_SYNC["100% SYNCHRONIZED\n(synchronized = true)"]
    DIFF["Discrepancy Detected:\n• missingInInboxEventIds\n• failedInInboxEventIds\n• missingSerials / statusMismatches"]
    REPLAY_CMD["POST /api/v1/admin/reconciliation/replay\nPublishes REPLAY_EVENTS Command\nto kms.reconciliation.request"]
    KMS_REPLAY{"Does Serial Exist\nin kms.outbox_event?"}
    REPUBLISH["Re-Publish Existing OutboxEvent\nto ocsp.certificate.status"]
    SYNTHESIZE["Synthesize New OutboxEvent from kms.certificate,\nSave to kms.outbox_event & Publish to RabbitMQ"]

    KMS_OUTBOX --> MANIFEST --> VERIFY --> SYNC_CHECK
    SYNC_CHECK -->|No| IN_SYNC
    SYNC_CHECK -->|Yes| DIFF --> REPLAY_CMD --> KMS_REPLAY
    KMS_REPLAY -->|Yes| REPUBLISH --> VERIFY
    KMS_REPLAY -->|No (Missing from Outbox)| SYNTHESIZE --> VERIFY
```

---

## 4. Zone-by-Zone Reference Table

| Zone | Component | Port / Queue | Key Classes / Files |
|---|---|---|---|
| **Zone 2 (UI)** | `ocsp-console` | `:3002` | `SigningCertificatesPage.js`, `SigningCertValidityPage.js`, `InboxAuditPage.js`, `CertCheckerPage.js` |
| **Zone 2 (UI)** | `kms-console` | `:3001` | `CertificateAuthoritiesPage.tsx`, `KmsCertificatesPage.tsx`, `OutboxMonitorPage.tsx` |
| **Zone 3 (IAM)** | `ocsp-keycloak` | `:8081` | Realm `incert` (`/ocsp-administrators`, `/ocsp-operators`, `/ocsp-auditors`) |
| **Zone 4 (KMS)** | `kms-simulator` | `:8090` / `:3308` | `CertificateAuthorityService`, `RevocationService`, `OutboxRelayService`, `KmsReconciliationService` |
| **Zone 5 (Broker)** | `ocsp-rabbitmq` | `:5671` (mTLS), `:5672`, `:15672` | `ocsp.certificate.status`, `ocsp.certificate.status.dlq`, `ocsp.reconciliation.manifest`, `kms.reconciliation.request` |
| **Zone 6 (Responder)** | `ocsp-responder` | `:8080` / `:3307` | `OcspResponderService`, `SigningCertificateService`, `SigningCertificateValidityService`, `CertificateStatusConsumerService`, `InboxFailureRecorder`, `OutboxReconciliationService` |
| **Zone 7 (HSM)** | `ocsp-hsm` | Volumes `hsm-tokens`, `hsm-conf` | `init-hsm.sh`, `Pkcs11OcspSigner`, `SigningAlgorithm` |
| **Zone 8 (Client)** | `ocsp-client` | `:8082` | `OcspClientService`, `OcspClientController` |

