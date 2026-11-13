# ADR-006: Decoupling OCSP Responder and OCSP Client into Standalone Applications

## Status
Accepted

## Context
Earlier iterations placed the OCSP Responder and the OCSP Client in a single monolithic Maven module or application (`ocsp-app`).

While sharing code was convenient, it created architectural ambiguity:
1. In production, relying parties (clients, browsers, TLS terminators) run independently from OCSP Responders and private CAs.
2. The OCSP Client requires no database connection, no RabbitMQ broker connection, and no HSM access; it only requires a network connection to an OCSP responder and the trusted CA certificate to verify responses.
3. Combining them conflated client verification tests and server response generation.

## Decision
Split into two distinct standalone Spring Boot applications:
1. **`ocsp-responder` (Port 8080)**:
   - Contains only server-side capabilities: RFC 6960 responder endpoint (`/ocsp`), SoftHSM2 PKCS#11 signing, MariaDB status repository, RabbitMQ consumer, and authenticated Admin API.
2. **`ocsp-client` (Port 8082)**:
   - Standalone client test runner and verifier.
   - Generates RFC 6960 DER requests (with/without Nonce, POST/GET), parses OCSP responses, verifies cryptographic signatures against the CA certificate, and serves an interactive web test UI.
   - Completely independent from MariaDB, RabbitMQ, and HSM.

## Consequences
- **Positive**: Clean separation of roles matching real-world PKI deployments. Client can be scaled, tested, or deployed as a lightweight sidecar or CLI without database credentials.
- **Negative**: Requires separate Docker container and port allocation (`8080` vs `8082`).
