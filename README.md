# Incert OCSP Subsystem (v2.0)

> RFC 6960-compliant OCSP Infrastructure for Incert Private CA.  
> Architected with **Separated Standalone Applications**, **Keycloak IAM (OAuth2 / OIDC)**, **Dynamic Signing Certificate Rotation**, **RabbitMQ Event Bus**, **Dedicated SoftHSM2 (PKCS#11)**, and **Mantine v7 Dashboard**.  
> Stack: Java 25 · Spring Boot 4.0 · Keycloak 24 · RabbitMQ 3.13 · SoftHSM2 · MariaDB 10.11 · React 18 · Mantine v7

---

## Architecture Overview

```
                      ┌───────────────────────────────────────┐
                      │    Mantine Console (Port 3000)        │
                      │    [LoginPage / Keycloak SSO / UI]    │
                      └───────┬───────────────────────┬───────┘
       (Admin API + Auth)     │                       │ (RFC 6960 Test Checks)
                              ▼                       ▼
┌──────────────────┐      ┌───────────────────────┐       ┌───────────────────────┐
│     ocsp-hsm     │◄─────┤    ocsp-responder     │       │      ocsp-client      │
│  (Dedicated HSM  │ PKCS │      (Port 8080)      │       │      (Port 8082)      │
│    Container)    │ #11  │  Dual Auth (KEYCLOCK  │       │  Test Web Interface   │
│                  │      │    / SELF_MANAGED)    │       │  RFC 6960 Verifier    │
└──────────────────┘      │  Sign Cert Rotation   │       └───────────▲───────────┘
                          └──────────▲────────────┘                   │
                                     │ (JWT / JWKS)             (RFC 6960 /ocsp)
                          ┌──────────┴────────────┐                   │
                          │     Keycloak IAM      │                   │
                          │      (Port 8081)      │                   │
                          │   Groups & SSO Auth   │                   │
                          └──────────▲────────────┘                   │
                                     │                                │
                               (AMQP Events)                          │
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

### 1. Build Standalone Applications
Each application is completely independent and can be built either individually or via the helper script:

```bash
# Build all standalone services at once:
./scripts/build-all.sh

# Or build any service individually in its own directory:
(cd kms-simulator && mvn clean package -DskipTests)
(cd ocsp-responder && mvn clean package -DskipTests)
(cd ocsp-client && mvn clean package -DskipTests)
```

### 2. Run with Docker Compose
```bash
# Starts all services including Keycloak, Dedicated HSM, RabbitMQ, MariaDB, and Responder:
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
| **OCSP Console (Mantine)** | `3000` | [http://localhost:3000](http://localhost:3000) (Dashboard, Signing Certs, Inventory) | **Keycloak SSO / Token / API Key** |
| **Keycloak IAM** | `8081` | [http://localhost:8081](http://localhost:8081) (Realm: `incert`, Client: `ocsp-console`) | `admin` / `admin` (Admin Console) |
| **OCSP Responder Swagger UI** | `8080` | [http://localhost:8080/swagger-ui/index.html](http://localhost:8080/swagger-ui/index.html) (`/v3/api-docs`) | Public Docs (Supports Auth in UI) |
| **OCSP Client Swagger UI** | `8082` | [http://localhost:8082/swagger-ui/index.html](http://localhost:8082/swagger-ui/index.html) (`/v3/api-docs`) | Public Docs |
| **KMS Simulator Swagger UI** | `8090` | [http://localhost:8090/swagger-ui/index.html](http://localhost:8090/swagger-ui/index.html) (`/v3/api-docs`) | Public Docs |
| **OCSP Client Test Tool** | `8082` | [http://localhost:8082](http://localhost:8082) (Interactive test web tool) | Public UI |
| **KMS Simulator Portal** | `8090` | [http://localhost:8090](http://localhost:8090) (Certificate management UI) | Public UI |
| **OCSP Responder Protocol** | `8080` | [http://localhost:8080/ocsp](http://localhost:8080/ocsp) (`POST` DER · `GET /{b64url}`) | Public (RFC 6960) |
| **Signing Certs Admin API** | `8080` | [http://localhost:8080/api/v1/admin/signing-certificates](http://localhost:8080/api/v1/admin/signing-certificates) | **Bearer JWT** / **API Key** |
| **OCSP Responder Admin API** | `8080` | [http://localhost:8080/api/v1/admin](http://localhost:8080/api/v1/admin) (Stats, Revocations) | **Bearer JWT** / **API Key** |
| **OCSP Responder Inbox API** | `8080` | [http://localhost:8080/api/v1/admin/inbox](http://localhost:8080/api/v1/admin/inbox) (Event Stream & Received Inbox) | **Bearer JWT** / **API Key** |
| **OCSP Reconciliation API** | `8080` | [http://localhost:8080/api/v1/admin/reconciliation/verify](http://localhost:8080/api/v1/admin/reconciliation/verify) | **Bearer JWT** / **API Key** |
| **OCSP Responder Auth Config** | `8080` | [http://localhost:8080/api/v1/auth/config](http://localhost:8080/api/v1/auth/config) | Public config endpoint |
| **RabbitMQ Management** | `15672` | [http://localhost:15672](http://localhost:15672) (Web Management UI) | `guest` / `guest` |
| **RabbitMQ AMQP** | `5672` | `localhost:5672` (AMQP Broker) | `guest` / `guest` |
| **MariaDB** | `3307` | `localhost:3307` (Schemas: `ocsp`, `kms`) | `root` / `rootpassword` |

---

## Authentication Modes & Credentials

Authentication mode is configured via `security.auth-mode` (`AUTH_MODE: KEYCLOCK` or `SELF_MANAGED`).

### Keycloak Pre-Configured Users & Groups (`AUTH_MODE=KEYCLOCK`)

| User | Password | Group | Assigned Roles | Access Rights |
|---|---|---|---|---|
| **`admin`** | `changeme` | `/ocsp-administrators` | `ROLE_ADMIN`, `admin` | Full administrative control, signing cert rotation |
| **`operator`** | `changeme` | `/ocsp-operators` | `ROLE_ADMIN`, `ROLE_OPERATOR` | Operational revocation and testing |
| **`auditor`** | `changeme` | `/ocsp-auditors` | `ROLE_AUDITOR` | Read-only audit logs and reconciliation inspection |

### Machine & Break-Glass Access

| Type | Header / Value | Allowed Endpoints |
|---|---|---|
| **Admin API Key** | `X-API-KEY: incert-admin-secret-key` | All `/api/v1/admin/**` endpoints |
| **HTTP Basic Auth** | `admin:changeme` | Emergency break-glass fallback in both modes |

---

## Dynamic Signing Certificate Rotation

The subsystem includes full runtime rotation of OCSP response signing certificates:
- **Registry Table**: `signing_certificates` with audit timestamps and metadata.
- **Single Active Invariant**: Exactly one certificate is active at any time; activating a certificate deactivates all others atomically.
- **In-Memory HSM Switch**: `PUT /api/v1/admin/signing-certificates/{id}/activate` updates the PKCS#11 signer in-memory immediately without dropping connections or restarting containers.
- **Console UI**: Inspect, add from PEM, and rotate certificates at [http://localhost:3000/signing-cert](http://localhost:3000/signing-cert).

---

## Applications & Modules

| Module | Port | Description |
|---|---|---|
| [`hsm`](./hsm) | N/A | Dedicated containerized Hardware Security Module (SoftHSM2) running in Docker, managing non-extractable RSA-3072 delegated signing keys, tokens, and PKCS#11 storage. |
| [`keycloak`](./keycloak) | `8081` | OAuth2 / OIDC Identity & Access Management server with pre-seeded `incert` realm, groups, users, and tokens. |
| [`ocsp-responder`](./ocsp-responder) | `8080` | RFC 6960 OCSP responder with dynamic signing certificate registry, PKCS#11 HSM integration, RabbitMQ inbox consumer, and dual-mode Spring Security. |
| [`ocsp-client`](./ocsp-client) | `8082` | Standalone OCSP Client application with embedded web UI for testing RFC 6960 requests (with/without nonce, POST/GET) and verifying cryptographic signatures against the CA cert. |
| [`kms-simulator`](./kms-simulator) | `8090` | Source of truth for certificates and revocation lifecycle. Test PKI generator, transactional outbox pattern, embedded web UI, and RabbitMQ publisher. |
| [`ocsp-console`](./ocsp-console) | `3000` | Full administrative React 18 single page application with Mantine v7 components, Keycloak SSO redirect flow, and dynamic signing certificate management UI. |

---

## Testing

```bash
# 1. Run unit tests on individual standalone applications:
(cd kms-simulator && mvn test)
(cd ocsp-responder && mvn test)
(cd ocsp-client && mvn test)

# 2. Run end-to-end integration test suite (with live containers):
./scripts/e2e-test.sh
```
