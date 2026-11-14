# ADR-011: OCSP Login TLS Activation / Deactivation & Certificate Authentication

## Status
Accepted

## Context
Following the implementation of mutual TLS (mTLS) for RabbitMQ and configurable TLS activation toggles, administrators required the ability to activate and deactivate TLS for **OCSP Responder login and console authentication**.
Specifically:
1. Operators require a configuration property in `application.yml` (`security.tls.enabled`) to enable or disable TLS enforcement for OCSP login.
2. When TLS is **active**:
   - Clients and administrators can authenticate using mTLS Client Certificates (e.g., enrolled PKI admin certificates).
   - Responses and session state indicate active transport security (`tlsEnabled: true`).
3. When TLS is **deactivated**:
   - Client certificate / mTLS authentication attempts are safely rejected with HTTP 400 Bad Request, explicitly explaining that TLS authentication is deactivated in application configuration.
   - Traditional credential authentication (Keycloak SSO / Bearer JWT, Username & Password, or API Key) remains available while flagging that transport security is deactivated.
4. The administrative UI (`ocsp-console`) and embedded responder login (`static/login.html`) must display real-time TLS status badges (`TLS: Active` vs `TLS: Deactivated`), provide an mTLS certificate authentication tab, and offer quick activation/deactivation controls.

## Decision
1. **Application Property**:
   Added `security.tls.enabled: ${SECURITY_TLS_ENABLED:${AUTH_TLS_ENABLED:${TLS_ENABLED:true}}}` in `ocsp-responder/src/main/resources/application.yml`.
2. **Auth API Configuration & Status**:
   - `GET /api/v1/auth/config`: Includes `"tlsEnabled": boolean` alongside `authMode` and `keycloak` config.
   - `GET /api/v1/auth/tls` & `POST /api/v1/auth/tls`: Provides an administrative status inspection and runtime toggle endpoint (`{"enabled": boolean}`).
   - `GET /api/v1/auth/me`: Returns `"tlsEnabled": boolean` for session auditing.
3. **Login Authentication Flow**:
   - `POST /api/v1/auth/login`:
     - Accepts `clientCert` (subject DN or PEM-encoded certificate) in `LoginPayload`.
     - When `tlsEnabled == true`: Verifies identity and grants `ROLE_ADMIN` access with `authType: "TLS_CLIENT_CERT"`.
     - When `tlsEnabled == false`: Rejects `clientCert` authentication with HTTP 400 Bad Request and an explicit error message.
4. **Console UI Integration**:
   - `LoginPage.tsx`: Added TLS badge (`TLS: Active` in teal / `TLS: Deactivated` in gray), an interactive toggle control, and a dedicated `mTLS Cert` authentication tab with warning banners when deactivated.
   - `login.html`: Added real-time TLS badge, certificate authentication tab, and quick toggle capability.
5. **Automated Testing**:
   - Unit tests in `AuthControllerTest.java` verifying TLS configuration, runtime toggling, successful certificate login when active, and 400 rejection when deactivated.
   - End-to-end test suite (`scripts/e2e-test.sh` Test n: 5/5 sub-tests) validating end-to-end activation, deactivation, and client cert enforcement.

## Consequences
- **Positive**: Full operational flexibility to enforce strict mTLS login in high-security environments or deactivate it in test/development scenarios where TLS offloading occurs upstream.
- **Security**: Disabling TLS clearly rejects client certificate authentication, avoiding false assumptions of transport-level peer verification when TLS is inactive.

