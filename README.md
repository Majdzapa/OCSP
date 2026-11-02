# OCSP Subsystem — Incert Private CA

> RFC 6960-compliant OCSP Responder for the company's private Certificate Authority (Incert).
> Spring Boot 3 · RabbitMQ 3.13 · MariaDB 10.11 · React 18 + TypeScript

---

## Quick Start (local dev — no backend needed)

```bash
# Start the React admin console with mock API
cd ocsp-console
npm install
npm run dev
# → http://localhost:5173

# To use the real Spring Boot backend instead:
VITE_USE_REAL_API=true npm run dev
```

## Full stack with Docker Compose

```bash
docker-compose up --build
```

| Service | URL | Notes |
|---|---|---|
| OCSP endpoint | http://localhost:8080/ocsp | `POST` DER · `GET /{b64url}` |
| Sync service health | http://localhost:8081/actuator/health | |
| Admin API | http://localhost:8082/api/v1/admin | OAuth2/OIDC required |
| React console | http://localhost:3000 | |
| RabbitMQ UI | http://localhost:15672 | guest / guest |
| MariaDB | localhost:3307 | DB: `ocsp` |

---

## Modules

| Module | Description |
|---|---|
| [`ocsp-responder`](./ocsp-responder) | Public `POST/GET /ocsp` endpoint, Caffeine L1 + MariaDB L2 cache, KMS signing delegation |
| [`ocsp-sync-service`](./ocsp-sync-service) | RabbitMQ consumer, idempotent revocation upsert, cache-invalidation publisher, reconciliation job |
| [`ocsp-admin-api`](./ocsp-admin-api) | Internal REST API (OAuth2/OIDC) — dashboard stats, cache explorer, revocation feed |
| [`ocsp-console`](./ocsp-console) | React 18 + MUI admin dashboard |

---

## Documentation

- 📐 **[ARCHITECTURE.md](./ARCHITECTURE.md)** — Full sequence diagrams, ERD, RabbitMQ topology, deployment blueprint, security boundaries

---

## Database

Flyway migrations in [`db/migrations/`](./db/migrations/):

| Migration | Description |
|---|---|
| `V1__initial_schema.sql` | 4 tables: `revocation_status`, `ocsp_response_cache`, `cert_event_audit`, `ocsp_signing_cert` |
| `V2__db_users.sql` | Least-privilege DB users per service (`ocsp_reader`, `ocsp_writer`, `ocsp_admin`) |

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Two-layer cache (Caffeine L1 + MariaDB L2) | Sub-ms hot path without a Redis dependency; L2 shared across the fleet |
| Event-driven sync (RabbitMQ) | OCSP read path never blocks on KMS transactional writes |
| Delegated OCSP signing cert | CA key stays in HSM; short-lived cert with `id-pkix-ocsp-nocheck` |
| Idempotent upsert via `source_event_id` | Safe RabbitMQ redelivery — no duplicate status changes |
| Stateless responder nodes | Any node serves any request; HPA scales on CPU/RPS |

---

## Environment Variables

All services are fully configured via environment variables — see each module's `application.yml`.

| Variable | Default | Used by |
|---|---|---|
| `MARIADB_HOST` | `localhost` | all Spring services |
| `MARIADB_DB` | `ocsp` | all |
| `MARIADB_PASSWORD` | `changeme` | all |
| `RABBITMQ_HOST` | `localhost` | all |
| `KMS_SIGNING_API_URL` | `http://kms-internal:8443/api/v1/sign` | ocsp-responder |
| `KMS_OCSP_KEY_REF` | `ocsp-signing-key-01` | ocsp-responder |
| `OIDC_ISSUER_URI` | `https://sso.company.internal/realms/company` | ocsp-admin-api |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | ocsp-admin-api |
| `VITE_USE_REAL_API` | _(unset = mock mode)_ | ocsp-console |
