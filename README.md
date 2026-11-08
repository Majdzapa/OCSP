# Incert OCSP Subsystem (v2.0)

> RFC 6960-compliant OCSP Responder for Incert Private CA.
> Re-architected with **Kafka (KRaft)**, **Spring Modulith**, **SoftHSM2 (PKCS#11)**, and **Transactional Outbox**.
> Stack: Java 21 · Spring Boot 3.3 · Spring Modulith 1.2 · Apache Kafka 3.8 · MariaDB 10.11 · React 18

---

## Quick Start

### 1. Build backend modules
```bash
mvn clean verify
```

### 2. Run with Docker Compose
```bash
docker compose up --build -d
```

### 3. Run End-to-End Test Suite
```bash
./scripts/e2e-test.sh
```

---

## Exposed Ports

| Service | Port | Endpoint / Description |
|---|---|---|
| **Admin Console** | `3000` | http://localhost:3000 (React 18 SPA + Nginx reverse proxy) |
| **OCSP Responder** | `8080` | http://localhost:8080/ocsp (`POST` DER · `GET /{b64url}`) |
| **Admin API** | `8080` | http://localhost:8080/api/v1/admin (Dashboard, Cache, Revocation Feed) |
| **KMS Simulator** | `8090` | http://localhost:8090/kms (Cert inventory, manual revoke/unrevoke, job triggers) |
| **Kafka Broker** | `9092` | localhost:9092 (KRaft mode; no ZooKeeper) |
| **MariaDB** | `3307` | localhost:3307 (Schemas: `ocsp`, `kms`) |

---

## Modules

| Module | Description |
|---|---|
| [`kms-simulator`](./kms-simulator) | Source of truth for certificates. Test PKI generator, transactional outbox pattern, scheduled revocation job, Kafka event publisher. |
| [`ocsp-app`](./ocsp-app) | Unified Spring Modulith application. Modules: `responder` (RFC 6960), `status` (Caffeine L1 + DB), `signing` (SoftHSM2 PKCS#11), `sync` (Kafka consumer), `admin` (management REST API). |
| [`ocsp-console`](./ocsp-console) | React 18 + TypeScript + MUI admin interface. Points to `ocsp-app` via Nginx reverse proxy. |

---

## Key Design Decisions & ADRs

| Decision | Summary | ADR Reference |
|---|---|---|
| **Kafka over RabbitMQ** | Key-ordered partitions (`issuerKeyHash:serial`) guarantee strict chronological order per certificate. Replay from offset eliminates external sync APIs. | [ADR-001](./docs/adr/ADR-001-kafka-over-rabbitmq.md) |
| **Spring Modulith** | Single container deployable unit. In-process cache invalidation replaces network messaging. Enforced via `verify()` and ArchUnit tests. | [ADR-002](./docs/adr/ADR-002-modulith-over-microservices.md) |
| **SoftHSM2 (PKCS#11)** | Cryptographic signing executed inside HSM token via SunPKCS11. Private key is non-extractable; zero private key material stored in container filesystem. | [ADR-003](./docs/adr/ADR-003-softhsm-pkcs11-signing.md) |
| **Transactional Outbox** | Status mutations and outbox events committed in the same MariaDB transaction, relayed to Kafka asynchronously with `enable.idempotence=true`. | [ADR-004](./docs/adr/ADR-004-transactional-outbox-pattern.md) |

---

## Environment Variables

| Variable | Default | Component | Description |
|---|---|---|---|
| `MARIADB_HOST` | `mariadb` | all | MariaDB host |
| `MARIADB_PORT` | `3306` | all | MariaDB port |
| `MARIADB_DB` | `ocsp` | `ocsp-app` | OCSP schema name |
| `MARIADB_KMS_DB` | `kms` | `kms-simulator` | KMS schema name |
| `MARIADB_USER` | `ocsp_app` | `ocsp-app` | OCSP database user |
| `MARIADB_KMS_USER` | `kms_app` | `kms-simulator` | KMS database user |
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:29092` | all | Kafka cluster bootstrap servers |
| `HSM_ENABLED` | `true` | `ocsp-app` | Enable PKCS#11 signing (`false` falls back to software signer) |
| `HSM_PKCS11_LIBRARY` | `/usr/lib/softhsm/libsofthsm2.so` | `ocsp-app` | PKCS#11 shared object path |
| `HSM_TOKEN_LABEL` | `ocsp-signing` | `ocsp-app` | SoftHSM2 token label |
| `HSM_KEY_LABEL` | `ocsp-signing-key` | `ocsp-app` | Key pair label inside token |
| `HSM_PIN` | `1234` | `ocsp-app` | User PIN for token authentication |
| `PKI_DIR` | `/data/pki` | all | Shared volume path for test PKI exports |
| `KMS_JOB_REVOCATION_ENABLED`| `false` | `kms-simulator` | Background random revocation simulation job |
| `KMS_JOB_REVOCATION_CRON` | `0/30 * * * * *` | `kms-simulator` | Revocation simulation frequency |

---

## Testing

```bash
# 1. Unit & Modulith verification tests
mvn test

# 2. End-to-end integration test (with live containers)
./scripts/e2e-test.sh
```
