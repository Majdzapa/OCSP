# OCSP Subsystem — Architecture & Blueprint

> **Version**: 1.0 · **Stack**: Java 21 · Spring Boot 3.3 · RabbitMQ 3.13 · MariaDB 10.11 · React 18

---

## Table of Contents

1. [System Blueprint](#1-system-blueprint)
2. [Sequence: OCSP Request Processing](#2-sequence-ocsp-request-processing)
3. [Sequence: Certificate Revocation Propagation](#3-sequence-certificate-revocation-propagation)
4. [Sequence: Cache Invalidation](#4-sequence-cache-invalidation)
5. [Sequence: Hourly Reconciliation](#5-sequence-hourly-reconciliation)
6. [Sequence: OCSP Signing Cert Rotation](#6-sequence-ocsp-signing-cert-rotation)
7. [Sequence: Admin Console — Manual Cache Invalidation](#7-sequence-admin-console--manual-cache-invalidation)
8. [Data Model ERD](#8-data-model-erd)
9. [RabbitMQ Topology](#9-rabbitmq-topology)
10. [Deployment Blueprint](#10-deployment-blueprint)
11. [Security Boundary Diagram](#11-security-boundary-diagram)

---

## 1. System Blueprint

```mermaid
graph TB
    subgraph EXTERNAL["External / Relying Parties"]
        RP["🌐 Relying Parties<br/>(browsers, mTLS services,<br/>VPN gateways, partner APIs)"]
        OPS["👤 Operators<br/>(PKI team, on-call)"]
    end

    subgraph KMS_ZONE["KMS / HSM Zone  🔒"]
        KMS["Incert Private CA<br/>+ KMS / HSM<br/>────────────────<br/>• Issues certificates<br/>• Revokes certificates<br/>• Signs OCSP responses<br/>• Issues delegated OCSP cert<br/>• Hosts signing private key"]
    end

    subgraph MQ["Messaging Layer"]
        RMQ["RabbitMQ 3.13<br/>────────────────<br/>Exchange: cert.events<br/>Queue: ocsp.status.sync<br/>Queue: ocsp.status.sync.dlq<br/>Queue: ocsp.cache.invalidate<br/>Queue: ocsp.audit.log"]
    end

    subgraph OCSP_ZONE["OCSP Service Zone"]
        RESP["ocsp-responder<br/>:8080<br/>────────────────<br/>POST /ocsp<br/>GET /ocsp/{b64}<br/>Caffeine L1 cache<br/>Bouncy Castle parser"]

        SYNC["ocsp-sync-service<br/>:8081<br/>────────────────<br/>RabbitMQ consumer<br/>Idempotent upsert<br/>Cache-invalidation pub<br/>Reconciliation job"]

        ADMIN_API["ocsp-admin-api<br/>:8082<br/>────────────────<br/>Dashboard stats<br/>Cache explorer<br/>Revocation feed<br/>OAuth2 / OIDC guard"]

        CONSOLE["ocsp-console<br/>:3000/5173<br/>────────────────<br/>React 18 + MUI<br/>Dashboard<br/>Cache Explorer<br/>Revocation Feed<br/>Signing Cert panel"]
    end

    subgraph DB["Data Layer"]
        MARIA["MariaDB 10.11<br/>────────────────<br/>revocation_status<br/>ocsp_response_cache<br/>cert_event_audit<br/>ocsp_signing_cert"]
    end

    subgraph OBSERVE["Observability"]
        PROM["Prometheus<br/>+ Grafana"]
        OTEL["OpenTelemetry<br/>Collector"]
    end

    RP -- "DER OCSPRequest" --> RESP
    RESP -- "DER OCSPResponse" --> RP
    KMS -- "cert.issued / cert.revoked" --> RMQ
    RMQ -- "ocsp.status.sync" --> SYNC
    SYNC -- "upsert" --> MARIA
    SYNC -- "ocsp.cache.invalidate" --> RMQ
    RMQ -- "invalidation signal" --> RESP
    RESP -- "L2 cache R/W" --> MARIA
    RESP -- "sign TBS bytes" --> KMS
    KMS -- "signature bytes" --> RESP
    ADMIN_API -- "SELECT" --> MARIA
    ADMIN_API -- "publish invalidation" --> RMQ
    OPS -- "HTTPS + OIDC JWT" --> CONSOLE
    CONSOLE -- "REST /api/v1/admin/**" --> ADMIN_API
    RESP -- "metrics + traces" --> PROM
    SYNC -- "metrics + traces" --> PROM
    ADMIN_API -- "metrics" --> PROM
    RESP --> OTEL
    SYNC --> OTEL
```

---

## 2. Sequence: OCSP Request Processing

This is the **hot path** — the critical path of every TLS/mTLS handshake that triggers an OCSP check.

```mermaid
sequenceDiagram
    autonumber
    participant RP   as Relying Party<br/>(browser / mTLS client)
    participant LB   as Load Balancer<br/>(WAF / Reverse Proxy)
    participant RESP as ocsp-responder<br/>OcspController
    participant SVC  as OcspProcessingService
    participant L1   as Caffeine L1 Cache<br/>(in-JVM)
    participant L2   as MariaDB L2 Cache<br/>ocsp_response_cache
    participant DB   as MariaDB<br/>revocation_status
    participant KMS  as KMS Signing API<br/>(mTLS)

    RP->>LB: POST /ocsp (DER OCSPRequest)
    LB->>RESP: Forward request
    RESP->>SVC: process(derBytes)

    Note over SVC: Parse DER → extract CertID<br/>(issuerNameHash, issuerKeyHash, serial)<br/>Enforce 10 KB size limit

    SVC->>L1: getIfPresent(cacheKey)

    alt L1 HIT (no nonce)
        L1-->>SVC: DER OCSPResponse
        Note over SVC: p95 < 1 ms path
        SVC-->>RESP: cached DER
        RESP-->>LB: 200 OK (application/ocsp-response)
        LB-->>RP: DER OCSPResponse

    else L1 MISS → try L2
        L1-->>SVC: null
        SVC->>L2: findValidByCacheKey(key, now)

        alt L2 HIT (no nonce)
            L2-->>SVC: OcspResponseCache entity
            SVC->>L1: put(key, derBytes)  // warm L1
            Note over SVC: p95 < 10 ms path
            SVC-->>RESP: cached DER
            RESP-->>LB: 200 OK
            LB-->>RP: DER OCSPResponse

        else L2 MISS → build fresh response
            L2-->>SVC: empty
            SVC->>DB: findByCertId(inh, ikh, serial)

            alt Certificate KNOWN
                DB-->>SVC: RevocationStatus {GOOD | REVOKED | UNKNOWN}
            else Certificate NOT FOUND
                DB-->>SVC: empty → status = UNKNOWN
            end

            Note over SVC: Build BasicOCSPResp<br/>Set thisUpdate, nextUpdate (+1h)<br/>Echo nonce if present

            SVC->>KMS: POST /api/v1/sign<br/>{keyRef, tbsBytes, algorithm}
            Note over KMS: Private key stays in HSM.<br/>Only signature bytes returned.
            KMS-->>SVC: {signatureBytes}

            Note over SVC: Assemble OCSPResponse<br/>Embed signer cert chain

            alt No nonce (cacheable)
                SVC->>L2: save(cacheKey, derBytes, nextUpdate)
                SVC->>L1: put(cacheKey, derBytes)
            end

            Note over SVC: p95 < 300 ms path
            SVC-->>RESP: fresh DER
            RESP-->>LB: 200 OK
            LB-->>RP: DER OCSPResponse
        end
    end

    Note over RP: Verify signature using<br/>OCSP responder cert chain.<br/>Trust decision made.
```

---

## 3. Sequence: Certificate Revocation Propagation

From the operator revoking a cert in the KMS to every OCSP responder reflecting `revoked` — target **< 60 seconds**.

```mermaid
sequenceDiagram
    autonumber
    participant OPS  as PKI Operator
    participant KMS  as Incert KMS
    participant HSM  as HSM
    participant RMQ  as RabbitMQ<br/>cert.events exchange
    participant SYNC as ocsp-sync-service<br/>CertificateEventConsumer
    participant PROC as CertificateEventProcessor
    participant DB   as MariaDB<br/>revocation_status
    participant AUDIT as MariaDB<br/>cert_event_audit
    participant INV  as RabbitMQ<br/>ocsp.cache.invalidate
    participant RESP as ocsp-responder<br/>(all nodes)
    participant L1   as Caffeine L1 (each node)
    participant L2   as MariaDB<br/>ocsp_response_cache

    OPS->>KMS: Revoke certificate (serial, reason)
    KMS->>HSM: CRL signing (internal)
    HSM-->>KMS: signed
    KMS->>RMQ: publish CertificateRevoked event<br/>{eventId, serial, reason, revocationTime, issuerHashes}
    Note over KMS,RMQ: Publisher confirms enabled —<br/>KMS waits for RabbitMQ ack

    RMQ-->>SYNC: Deliver to ocsp.status.sync queue
    SYNC->>AUDIT: INSERT cert_event_audit {status=RECEIVED}

    Note over SYNC: Manual acknowledgment —<br/>message stays on queue until<br/>MariaDB transaction commits

    SYNC->>PROC: process(event)

    PROC->>DB: updateByCertId(serial, REVOKED, reason, time)
    Note over PROC,DB: Idempotent: if 0 rows updated → INSERT.<br/>Unique constraint on source_event_id<br/>prevents duplicate processing.
    DB-->>PROC: committed ✓

    PROC->>AUDIT: UPDATE {status=PROCESSED, processedAt=now}

    PROC->>INV: publish StatusChanged<br/>{issuerNameHashHex, issuerKeyHashHex, serialHex}
    INV-->>RESP: Deliver to ocsp.cache.invalidate<br/>(all responder nodes subscribed)

    RESP->>L1: invalidate(cacheKey)
    RESP->>L2: DELETE WHERE cache_key = cacheKey

    SYNC->>RMQ: basicAck(deliveryTag)
    Note over SYNC,RMQ: Only acked after full commit.<br/>On exception → basicNack → DLQ.

    Note over RESP: ✅ Next OCSP query for this<br/>certificate will hit DB, build<br/>fresh REVOKED response, re-cache.
    Note over OPS: Total propagation time:<br/>KMS publish → responder reflects REVOKED<br/>Target SLA: < 60 seconds
```

---

## 4. Sequence: Cache Invalidation

Detail of the cache eviction flow across a fleet of responder nodes.

```mermaid
sequenceDiagram
    autonumber
    participant PROC as CertificateEventProcessor<br/>(sync-service)
    participant RMQ  as RabbitMQ<br/>ocsp.internal exchange
    participant Q    as ocsp.cache.invalidate queue
    participant N1   as Responder Node 1<br/>CacheInvalidationListener
    participant N2   as Responder Node 2<br/>CacheInvalidationListener
    participant N3   as Responder Node N<br/>CacheInvalidationListener
    participant MGR  as OcspResponseCacheManager

    PROC->>RMQ: convertAndSend(exchange, routingKey, {hashes})
    RMQ->>Q: route message (direct binding)

    par All responder nodes consume from the same queue
        Q-->>N1: onStatusChanged(payload)
        N1->>MGR: evict(cacheKey)
        MGR->>MGR: caffeineL1Cache.invalidate(key)
        MGR->>MGR: l2Repository.deleteById(key)
        Note over N1: L1 + L2 cleared ✓

        Q-->>N2: onStatusChanged(payload)
        N2->>MGR: evict(cacheKey)

        Q-->>N3: onStatusChanged(payload)
        N3->>MGR: evict(cacheKey)
    end

    Note over N1,N3: Any node that receives the<br/>next OCSP query for this cert<br/>will get a cache MISS and build<br/>a fresh REVOKED response.

    Note over MGR: Eviction failure is non-fatal.<br/>Entry expires naturally at nextUpdate.<br/>Metric: ocsp.cache.eviction.failure
```

---

## 5. Sequence: Hourly Reconciliation

Belt-and-braces defense against missed RabbitMQ events (message loss, partition, KMS bug).

```mermaid
sequenceDiagram
    autonumber
    participant SCH  as Spring @Scheduled<br/>cron: 0 0 * * * *
    participant JOB  as ReconciliationJob
    participant DB   as MariaDB<br/>revocation_status
    participant KMS  as KMS Reconciliation API<br/>(mTLS)
    participant PROC as CertificateEventProcessor
    participant PROM as Prometheus / Alertmanager

    SCH->>JOB: reconcile() [every hour]
    JOB->>DB: COUNT(*) WHERE status = 'REVOKED'
    DB-->>JOB: localRevokedCount

    JOB->>KMS: GET /api/v1/ocsp/reconciliation
    Note over KMS: Returns checksum of all<br/>revoked serial numbers

    KMS-->>JOB: {revokedCount, checksum}

    alt Counts match ✓
        JOB->>PROM: ocsp.reconciliation.discrepancy = 0
        JOB->>PROM: ocsp.reconciliation.runs++
        Note over JOB: Healthy — no action needed
    else Discrepancy detected ⚠️
        JOB->>PROM: ocsp.reconciliation.discrepancy = N
        PROM-->>PROM: Fire alert → PagerDuty / Slack

        JOB->>KMS: GET /api/v1/revocations?since=lastCheckpoint
        KMS-->>JOB: [{serial, reason, time, hashes}, ...]

        loop For each missing revocation
            JOB->>PROC: process(syntheticEvent)
            PROC->>DB: UPSERT revocation_status
        end

        Note over JOB: Gap closed.<br/>Log warning with diff details.
    end
```

---

## 6. Sequence: OCSP Signing Cert Rotation

The delegated signing certificate has a short lifetime (90 days). Rotation is automated via the KMS.

```mermaid
sequenceDiagram
    autonumber
    participant KMS  as Incert KMS<br/>(cert lifecycle manager)
    participant HSM  as HSM
    participant DB   as MariaDB<br/>ocsp_signing_cert
    participant RESP as ocsp-responder<br/>KmsSigningService
    participant PROM as Prometheus / Alertmanager
    participant OPS  as PKI Operator (alert recipient)
    participant CONS as React Console<br/>Signing Cert panel

    Note over KMS: T-14 days before current cert expiry

    KMS->>PROM: expose metric ocsp_signing_cert_days_remaining = 14
    PROM-->>OPS: 🟡 Alert: Signing cert expires in 14 days

    Note over KMS: Auto-rotation trigger (T-14)

    KMS->>HSM: Generate new RSA-4096 key pair
    HSM-->>KMS: newKeyReference (opaque handle)

    KMS->>KMS: Issue new OCSP signing cert<br/>(EKU: id-kp-OCSPSigning,<br/>Extension: id-pkix-ocsp-nocheck,<br/>Lifetime: 90 days,<br/>Issuer: Incert-Root-CA-01)

    KMS->>DB: INSERT ocsp_signing_cert<br/>{serial, not_before, not_after, is_active=false, kms_key_reference}

    Note over KMS: Overlap period — both old and new cert valid

    KMS->>DB: UPDATE ocsp_signing_cert SET is_active=true WHERE new
    KMS->>DB: UPDATE ocsp_signing_cert SET is_active=false WHERE old

    RESP->>KMS: [startup/refresh] GET /api/v1/ocsp/signing-cert/active
    KMS-->>RESP: {keyReference, certChain}
    RESP->>RESP: Hot-reload new signer — zero downtime

    PROM-->>CONS: ocsp_signing_cert_days_remaining refreshed to 90
    CONS-->>OPS: ✅ Dashboard shows new 90-day countdown

    Note over KMS: T-7 and T-1 day alerts if rotation<br/>has NOT completed (safety net)
    PROM-->>OPS: 🔴 CRITICAL: cert expires in 7 days (if still old cert)
```

---

## 7. Sequence: Admin Console — Manual Cache Invalidation

An operator force-refreshes a specific certificate's cached OCSP response from the React console.

```mermaid
sequenceDiagram
    autonumber
    participant OPS  as PKI Operator
    participant UI   as React Console<br/>CacheExplorer.tsx
    participant AXIOS as Axios client<br/>(Bearer JWT)
    participant SEC  as SecurityConfig<br/>(JWT validation)
    participant CTRL as CacheController<br/>ocsp-admin-api
    participant SVC  as CacheManagementService
    participant DB   as MariaDB<br/>ocsp_response_cache
    participant RMQ  as RabbitMQ<br/>ocsp.cache.invalidate
    participant RESP as ocsp-responder nodes
    participant AUDIT as Audit Log

    OPS->>UI: Click 🗑 on cache entry (cacheKey)
    UI->>UI: window.confirm("Invalidate?")
    OPS->>UI: Confirm ✓

    UI->>AXIOS: DELETE /api/v1/admin/cache/{cacheKey}
    AXIOS->>SEC: Validate Bearer JWT<br/>(issuer, expiry, ROLE_OCSP_ADMIN)

    alt JWT invalid / missing OCSP_ADMIN role
        SEC-->>UI: 401 / 403
        UI-->>OPS: ❌ Access denied
    else JWT valid + ROLE_OCSP_ADMIN
        SEC->>CTRL: invalidate(cacheKey, jwt.sub)
        CTRL->>SVC: invalidate(cacheKey, operatorId)

        SVC->>DB: DELETE FROM ocsp_response_cache WHERE cache_key = ?
        DB-->>SVC: deleted ✓

        SVC->>RMQ: publish {cacheKey, triggeredBy: "manual", operatorId}
        RMQ-->>RESP: Deliver to all responder nodes
        RESP->>RESP: L1 caffeineL1Cache.invalidate(key)

        SVC->>AUDIT: INSERT audit_log {operatorId, cacheKey, action: INVALIDATE, ts}

        CTRL-->>UI: 204 No Content
        UI-->>OPS: ✅ Entry invalidated — refreshing table…
        UI->>AXIOS: GET /api/v1/admin/cache (reload)
    end
```

---

## 8. Data Model ERD

```mermaid
erDiagram
    REVOCATION_STATUS {
        BIGINT id PK
        BINARY_20 issuer_name_hash "SHA-1 of issuer DN"
        BINARY_20 issuer_key_hash  "SHA-1 of issuer pubkey"
        VARBINARY_64 serial_number
        ENUM status              "GOOD | REVOKED | UNKNOWN"
        DATETIME revocation_time "null when GOOD"
        VARCHAR_40 revocation_reason "keyCompromise etc."
        DATETIME this_update
        DATETIME updated_at
        VARCHAR_64 source_event_id UK "idempotency key"
    }

    OCSP_RESPONSE_CACHE {
        CHAR_40 cache_key PK    "SHA-1 hex of CertID"
        MEDIUMBLOB der_response "DER OCSPResponse bytes"
        DATETIME this_update
        DATETIME next_update    "IDX — drives cleanup job"
        DATETIME created_at
    }

    CERT_EVENT_AUDIT {
        VARCHAR_64 event_id PK  "KMS event UUID"
        VARCHAR_40 event_type   "CertificateRevoked etc."
        VARBINARY_64 serial_number
        DATETIME received_at    "IDX"
        DATETIME processed_at
        ENUM status             "RECEIVED|PROCESSED|FAILED"
        TEXT error_message
    }

    OCSP_SIGNING_CERT {
        BIGINT id PK
        VARBINARY_64 serial_number
        DATETIME not_before
        DATETIME not_after      "IDX — expiry monitoring"
        BOOLEAN is_active       "IDX — single active cert"
        VARCHAR_128 kms_key_reference "opaque HSM handle"
        DATETIME created_at
    }

    REVOCATION_STATUS ||--o{ OCSP_RESPONSE_CACHE : "L2 cached for"
    CERT_EVENT_AUDIT   ||--|| REVOCATION_STATUS   : "updates via source_event_id"
```

---

## 9. RabbitMQ Topology

```mermaid
graph LR
    subgraph KMS["KMS Publisher"]
        P["Incert KMS<br/>(publisher confirms ON)"]
    end

    subgraph EXCHANGES["Exchanges"]
        CE["cert.events<br/>type: topic<br/>durable: true"]
        OI["ocsp.internal<br/>type: direct<br/>durable: true"]
    end

    subgraph QUEUES["Queues (all durable)"]
        SSQ["ocsp.status.sync<br/>x-dead-letter → DLQ"]
        DLQ["ocsp.status.sync.dlq<br/>Dead-letter queue"]
        CIQ["ocsp.cache.invalidate<br/>Consumed by all responders"]
        ALQ["ocsp.audit.log<br/>Feeds audit pipeline"]
    end

    subgraph CONSUMERS["Consumers"]
        SYNC["ocsp-sync-service<br/>manual-ack<br/>prefetch: 5"]
        RESP1["responder-node-1<br/>CacheInvalidationListener"]
        RESP2["responder-node-2<br/>CacheInvalidationListener"]
        RESPN["responder-node-N<br/>CacheInvalidationListener"]
        ADMIN["ocsp-admin-api<br/>(publishes invalidations)"]
    end

    P -- "cert.issued<br/>cert.revoked<br/>cert.hold<br/>cert.unrevoked" --> CE

    CE -- "routing: cert.*" --> SSQ
    CE -- "routing: cert.*" --> ALQ

    SSQ -- "on failure" --> DLQ
    SSQ --> SYNC

    SYNC -- "after DB commit" --> OI
    ADMIN --> OI

    OI -- "routing: ocsp.cache.invalidate" --> CIQ

    CIQ --> RESP1
    CIQ --> RESP2
    CIQ --> RESPN

    style DLQ fill:#f43f5e,color:#fff
    style CE fill:#6366f1,color:#fff
    style OI fill:#8b5cf6,color:#fff
```

---

## 10. Deployment Blueprint

```mermaid
graph TB
    subgraph INTERNET["Internet / Internal Network"]
        RP["Relying Parties"]
        OPS["Operators (VPN)"]
    end

    subgraph DMZ["DMZ / Public Zone"]
        WAF["WAF + Rate Limiter<br/>(nginx / cloud LB)"]
    end

    subgraph PRIVATE["Private Service Zone"]
        subgraph K8S["Kubernetes Cluster"]
            subgraph RESP_DEPLOY["ocsp-responder  (HPA: 2–10 pods)"]
                R1["Pod 1"]
                R2["Pod 2"]
                RN["Pod N"]
            end

            subgraph SYNC_DEPLOY["ocsp-sync-service  (1–2 pods)"]
                S1["Pod 1"]
            end

            subgraph ADMIN_DEPLOY["ocsp-admin-api  (2 pods)"]
                A1["Pod 1"]
                A2["Pod 2"]
            end

            subgraph CONSOLE_DEPLOY["ocsp-console  (nginx, 2 pods)"]
                C1["Pod 1"]
                C2["Pod 2"]
            end
        end

        subgraph DATA["Data Layer"]
            MDB["MariaDB Galera Cluster<br/>(primary + 2 replicas)"]
            RMQ_C["RabbitMQ Cluster<br/>(quorum queues, 3 nodes)"]
        end

        subgraph KMS_Z["KMS / HSM Zone"]
            KMS["Incert KMS + HSM<br/>(private key boundary)"]
        end

        subgraph OBS["Observability"]
            PROM2["Prometheus"]
            GRAF["Grafana"]
            OTEL2["OTel Collector"]
            ALERT["Alertmanager"]
        end
    end

    RP -- "HTTPS :443" --> WAF
    WAF -- "POST/GET /ocsp" --> RESP_DEPLOY
    OPS -- "HTTPS VPN" --> CONSOLE_DEPLOY
    CONSOLE_DEPLOY -- "/api/**" --> ADMIN_DEPLOY
    RESP_DEPLOY -- "read (ocsp_reader)" --> MDB
    SYNC_DEPLOY -- "write (ocsp_writer)" --> MDB
    ADMIN_DEPLOY -- "read (ocsp_admin)" --> MDB
    RESP_DEPLOY -- "cache invalidation" --> RMQ_C
    SYNC_DEPLOY -- "consume + publish" --> RMQ_C
    ADMIN_DEPLOY -- "publish invalidation" --> RMQ_C
    RESP_DEPLOY -- "mTLS sign API" --> KMS
    SYNC_DEPLOY -- "reconcile API" --> KMS
    KMS -- "cert events" --> RMQ_C
    RESP_DEPLOY --> PROM2
    SYNC_DEPLOY --> PROM2
    ADMIN_DEPLOY --> PROM2
    PROM2 --> GRAF
    PROM2 --> ALERT
    RESP_DEPLOY --> OTEL2
    SYNC_DEPLOY --> OTEL2
```

---

## 11. Security Boundary Diagram

```mermaid
graph LR
    subgraph PUBLIC["Public Zone (WAF protected)"]
        EP["/ocsp endpoint<br/>Port 8080<br/>Rate limited<br/>DER input, max 10KB"]
    end

    subgraph INTERNAL["Internal Zone (mTLS)"]
        SIGN["KMS Sign API<br/>mTLS client cert<br/>Returns: signature bytes only<br/>Key never leaves HSM"]
        ADMIN_INT["Admin API<br/>Port 8082<br/>Internal only<br/>OAuth2 JWT guard"]
    end

    subgraph HSM_ZONE["HSM Boundary 🔒"]
        HSM["Hardware Security Module<br/>────────────────────<br/>CA private key<br/>OCSP signing private key<br/>NEVER EXPORTED"]
    end

    subgraph DB_ZONE["Database Zone"]
        DB_RO["MariaDB<br/>ocsp_reader<br/>(SELECT only)"]
        DB_RW["MariaDB<br/>ocsp_writer<br/>(INSERT/UPDATE)"]
        DB_ADM["MariaDB<br/>ocsp_admin<br/>(SELECT + cache DELETE)"]
    end

    EP --> DB_RO
    EP --> SIGN
    SIGN --> HSM
    ADMIN_INT --> DB_ADM

    style HSM_ZONE fill:#1e1b4b,color:#c7d2fe
    style HSM fill:#312e81,color:#e0e7ff
    style PUBLIC fill:#0f172a,color:#94a3b8
    style INTERNAL fill:#0c1a2e,color:#94a3b8
```

> [!CAUTION]
> The HSM boundary is the most critical security control. `KmsBackedContentSigner` sends only TBS (to-be-signed) bytes to the KMS and receives only signature bytes back — the private key material is **never** transferred across any network boundary.

---

## Component Responsibilities Summary

| Component | Reads from | Writes to | Security boundary |
|---|---|---|---|
| `ocsp-responder` | `revocation_status` (RO), `ocsp_response_cache` (R/W), Caffeine L1 | `ocsp_response_cache` (L2 cache) | Public `/ocsp` behind WAF |
| `ocsp-sync-service` | RabbitMQ `ocsp.status.sync` | `revocation_status`, `cert_event_audit`, `ocsp.cache.invalidate` | Internal, no public exposure |
| `ocsp-admin-api` | `revocation_status`, `cert_event_audit`, `ocsp_signing_cert`, `ocsp_response_cache` | `ocsp.cache.invalidate` (via RMQ) | Internal, OAuth2/OIDC only |
| `ocsp-console` | Admin API REST | — | Internal, operators via VPN + SSO |
| `KMS / HSM` | — | `cert.events` (RMQ), signature bytes | Isolated HSM zone, mTLS ingress only |
