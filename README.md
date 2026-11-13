# Incert OCSP Subsystem (v2.0)

> RFC 6960-compliant OCSP Monolith (Responder & Client) for Incert Private CA.
> Architected with **Monolith Application**, **RabbitMQ**, **SoftHSM2 (PKCS#11)**, and **Direct Dynamic Signing (No Caching)**.
> Stack: Java 21 · Spring Boot 3.3 · RabbitMQ 3.13 · SoftHSM2 · MariaDB 10.11 · React 18

---

## Quick Start

### 1. Build backend modules
```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn clean package
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
| **OCSP Client API** | `8080` | http://localhost:8080/api/v1/client/check (Full RFC 6960 verification) |
| **Admin API** | `8080` | http://localhost:8080/api/v1/admin (Dashboard, Revocation Feed, Cert Check) |
| **KMS Simulator** | `8090` | http://localhost:8090/kms (Cert inventory, manual revoke/unrevoke, snapshot) |
| **RabbitMQ Management** | `15672` | http://localhost:15672 (guest/guest · Web UI) |
| **RabbitMQ AMQP** | `5672` | localhost:5672 (AMQP protocol) |
| **MariaDB** | `3307` | localhost:3307 (Schemas: `ocsp`, `kms`) |

---

## Modules

| Module | Description |
|---|---|
| [`kms-simulator`](./kms-simulator) | Source of truth for certificates. Test PKI generator, transactional outbox pattern, scheduled revocation job, RabbitMQ event publisher. |
| [`ocsp-app`](./ocsp-app) | Monolith application with clean layered architecture (`controller`, `service`, `repository`, `entity`, `signing`, `messaging`). Hosts both the **OCSP Responder** and the **OCSP Client** with SoftHSM2 PKCS#11 signing and RabbitMQ event consumption. |
| [`ocsp-console`](./ocsp-console) | React 18 + TypeScript + MUI admin interface. Proxied via Nginx to `ocsp-app` and `kms-simulator`. |

---

## Key Design Decisions

| Decision | Summary |
|---|---|
| **Monolith Architecture** | Combines OCSP Responder and OCSP Client in a single, simple Spring Boot application with standard layered packages. Eliminates distributed microservice network latency. |
| **Direct Signing (No Caching)** | Pre-signed L2 cache and L1 Caffeine cache removed. Every request queries the DB directly and generates a dynamic PKCS#11 signature. Guarantees 100% cryptographic freshness with zero stale cache windows. |
| **RabbitMQ Messaging** | Direct exchange (`incert.certificate.status`) and durable queue (`ocsp.certificate.status`) with dead-letter queue (`ocsp.certificate.status.dlq`). Monotonic `sequence` counter per certificate guarantees idempotency and out-of-order protection. |
| **SoftHSM2 (PKCS#11)** | Cryptographic signing executed inside HSM token via SunPKCS11. Private key is non-extractable (`CKA_EXTRACTABLE=FALSE`); zero private key material stored in container filesystem. |
| **Transactional Outbox** | Status mutations and outbox events committed in the same MariaDB transaction in KMS, relayed asynchronously to RabbitMQ. |

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
| `RABBITMQ_HOST` | `rabbitmq` | all | RabbitMQ host |
| `RABBITMQ_PORT` | `5672` | all | RabbitMQ AMQP port |
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
# 1. Unit & client verification tests
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test

# 2. End-to-end integration test (with live containers)
./scripts/e2e-test.sh
```
