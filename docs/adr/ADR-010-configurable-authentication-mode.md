# ADR-010: Configurable Authentication Mode (Keycloak OIDC vs Self-Managed)

## Status
Accepted

## Context
Organizations deploying the OCSP subsystem have varying authentication infrastructures:
1. Enterprise deployments require Single Sign-On (SSO) integrated with Keycloak / OpenID Connect (OIDC) identity providers and RBAC groups.
2. Lightweight, edge, or isolated dev environments prefer local self-managed authentication (Basic Auth & API Key) without external dependencies.

## Decision
1. **Configurable Authentication Mode Property**:
   - `security.auth-mode` property supporting `KEYCLOCK` (or `KEYCLOAK`) and `SELF_MANAGED`.
   - Defaults to `KEYCLOCK` in production / container deployment.
2. **Keycloak Integration**:
   - Keycloak container imported realm `incert` with predefined roles (`ROLE_ADMIN`, `ROLE_OPERATOR`, `ROLE_AUDITOR`) mapped from groups `/ocsp-administrators`, `/ocsp-operators`, `/ocsp-auditors`.
   - `KeycloakJwtAuthenticationConverter` extracts realm and resource access roles into Spring Security `GrantedAuthority` collections.
   - React Admin Console handles OIDC redirects to Keycloak login and parses JWT access tokens from URL fragments or PKCE callbacks.
3. **Emergency Break-Glass Fallback**:
   - In `KEYCLOCK` mode, HTTP Basic Auth (`admin` / `changeme`) and API Key (`X-API-KEY`) remain enabled as break-glass mechanisms for automated CLI scripts (`scripts/e2e-test.sh`) and out-of-band administrative access.

## Consequences
- **Positive**: Seamless enterprise SSO integration alongside standalone lightweight operation.
- **Positive**: Role-based access control (Admin, Operator, Auditor) natively enforced.
- **Negative**: Keycloak container increases memory footprint when running in full container stack.
