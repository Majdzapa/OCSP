# ADR-007: Admin API Authentication and Console Login Protection

## Status
Accepted

## Context
RFC 6960 mandates that OCSP validation endpoints (`/ocsp` and `/ocsp/**`) MUST be publicly accessible without authentication for relying parties to validate TLS and X.509 certificates.

However, the OCSP Responder also exposes administrative APIs (`/api/v1/admin/**`) for dashboard telemetry, revocation audit logs, and internal certificate checks. These endpoints must be protected from unauthorized access.

## Decision
1. **Spring Security Enforcement**:
   - Public access granted exclusively to `/ocsp`, `/ocsp/**`, `/actuator/health`, and `/api/v1/auth/**`.
   - All `/api/v1/admin/**` endpoints require `ROLE_ADMIN`.
2. **Dual Authentication Mechanisms**:
   - **HTTP Basic Auth**: For human administrative access (`admin` / `changeme`).
   - **API Key (`X-API-KEY`)**: For automated services and scripts (`incert-admin-secret-key`).
3. **Frontend Console Login Gate**:
   - Implemented `LoginPage` and `ProtectedRoute` in `ocsp-console` (Mantine v7).
   - Unauthenticated users are redirected to `/login`.
   - Credentials or API keys are stored in `localStorage` and attached via Axios request interceptors.
   - Any `401 Unauthorized` response immediately purges stored tokens and routes to `/login`.
4. **Embedded Responder Web Interface**:
   - `ocsp-responder` serves a static `/login.html` directly for headless/API developer testing.

## Consequences
- **Positive**: Hardened administrative surface while strictly maintaining RFC 6960 compliance for public certificate validation.
- **Negative**: Admin callers must supply credentials or `X-API-KEY`.
