# Incert OCSP Subsystem (v2.0)

> RFC 6960-compliant OCSP Infrastructure for Incert Private CA.  
> Architected with **Separated Standalone Applications**, **RabbitMQ Event Bus**, **SoftHSM2 (PKCS#11)**, **Spring Security Authentication**, and **Mantine v7 Dashboard**.  
> Stack: Java 21 · Spring Boot 3.3 · RabbitMQ 3.13 · SoftHSM2 · MariaDB 10.11 · React 18 · Mantine v7

---

## Architecture Overview

```
                      ┌───────────────────────────────────────┐
                      │    Mantine Console (Port 3000)        │
                      │    [LoginPage / Authenticated UI]     │
                      └───────┬───────────────────────┬───────┘
       (Admin API + Auth)     │                       │ (RFC 6960 Test Checks)
                              ▼                       ▼
                  ┌───────────────────────┐       ┌───────────────────────┐
                  │    ocsp-responder     │       │      ocsp-client      │
                  │      (Port 8080)      │       │      (Port 8082)      │
                  │  Spring Security Auth │       │  Test Web Interface   │
                  │  SoftHSM2 Dynamic PKI │       │  RFC 6960 Verifier    │
                  └──────────▲────────────┘       └───────────▲───────────┘
                             │                                │
                       (AMQP Events)                    (RFC 6960 /ocsp)
                             │                                │
                  ┌──────────┴────────────┐                   │
                  │     RabbitMQ Bus      │                   │
                  │      (Port 5672)      │                   │
                  └──────────▲────────────┘                   │
                             │                                │
                       (AMQP Outbox)                          │
                             │                                │
                  ┌──────────┴────────────┐                   │
                  │     kms-simulator     │                   │
                  │      (Port 8090)      │                   │
                  │   Web UI & Test PKI   │───────────────────┘
                  └───────────────────────┘
```

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

## Exposed Services & Interfaces

| Service | Port | Endpoint / Description | Authentication |
|---|---|---|---|
| **OCSP Console (Mantine)** | `3000` | [http://localhost:3000](http://localhost:3000) (Dashboard, KMS Inventory, Live Tests) | **Login Page** (`/login`) |
| **OCSP Client Test Tool** | `8082` | [http://localhost:8082](http://localhost:8082) (Interactive test web tool) | Public UI |
| **KMS Simulator Portal** | `8090` | [http://localhost:8090](http://localhost:8090) (Certificate management UI) | Public UI |
| **OCSP Responder Protocol** | `8080` | [http://localhost:8080/ocsp](http://localhost:8080/ocsp) (`POST` DER · `GET /{b64url}`) | Public (RFC 6960) |
| **OCSP Responder Admin API** | `8080` | [http://localhost:8080/api/v1/admin](http://localhost:8080/api/v1/admin) (Stats, Revocations) | **Basic Auth** or **API Key** |
| **OCSP Responder Auth API** | `8080` | [http://localhost:8080/api/v1/auth/login](http://localhost:8080/api/v1/auth/login) | Public auth endpoint |
| **OCSP Responder Login Page** | `8080` | [http://localhost:8080/login.html](http://localhost:8080/login.html) (Direct browser login tester) | Embedded UI |
| **RabbitMQ Management** | `15672` | [http://localhost:15672](http://localhost:15672) (Web Management UI) | `guest` / `guest` |
| **RabbitMQ AMQP** | `5672` | `localhost:5672` (AMQP Broker) | `guest` / `guest` |
| **MariaDB** | `3307` | `localhost:3307` (Schemas: `ocsp`, `kms`) | `root` / `rootpassword` |

---

## Credentials & Authentication

| Role / Scope | Username / Header | Password / Key | Allowed Endpoints |
|---|---|---|---|
| **Admin User (Basic Auth)** | `admin` | `changeme` | `/api/v1/admin/**` |
| **Admin Service (API Key)** | `X-API-KEY` | `incert-admin-secret-key` | `/api/v1/admin/**` |
| **RabbitMQ Admin** | `guest` | `guest` | `http://localhost:15672` |
| **MariaDB OCSP App** | `ocsp_app` | `changeme` | `ocsp` schema |
| **MariaDB KMS App** | `kms_app` | `changeme` | `kms` schema |
| **SoftHSM2 User PIN** | Token: `ocsp-signing` | `1234` | HSM dynamic signing |
| **SoftHSM2 SO PIN** | Token: `ocsp-signing` | `12345678` | HSM initialization |

---

## Applications & Modules

| Module | Port | Description |
|---|---|---|
| [`ocsp-responder`](./ocsp-responder) | `8080` | RFC 6960 OCSP responder with dynamic SoftHSM2 PKCS#11 signing (RSA-3072 / SHA256withRSA), RabbitMQ listener collecting status events into MariaDB, Spring Security protecting admin endpoints, and embedded login portal. |
| [`ocsp-client`](./ocsp-client) | `8082` | Standalone OCSP Client application with embedded web UI for testing RFC 6960 requests (with/without nonce, POST/GET) and verifying cryptographic signatures against the CA cert. |
| [`kms-simulator`](./kms-simulator) | `8090` | Source of truth for certificates and revocation lifecycle. Test PKI generator, transactional outbox pattern, embedded web UI, and RabbitMQ publisher. |
| [`ocsp-console`](./ocsp-console) | `3000` | Full administrative React 18 single page application with Mantine v7 components, protected by authentication gate (`/login`) with user session management, auto-logout on 401, and navbar user status. |

---

## Testing

```bash
# 1. Run unit tests across all applications
JAVA_HOME=/opt/homebrew/opt/openjdk@21 mvn test

# 2. Run end-to-end integration test (with live containers)
./scripts/e2e-test.sh
```
