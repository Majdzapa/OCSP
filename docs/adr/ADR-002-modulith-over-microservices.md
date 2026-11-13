# ADR-002: Modular Monolith (Spring Modulith) over Separate Microservices

## Status
Superseded by ADR-006: Decoupling OCSP Responder and OCSP Client into Standalone Applications

## Context
The previous system decomposed the OCSP subsystem into four distinct microservices: `ocsp-responder`, `ocsp-sync-service`, `ocsp-admin-api`, and `kms-mock`.
While this decoupled concerns, it introduced substantial operational overhead:
1. Four JVM runtimes consuming container memory.
2. Network roundtrips for cache invalidation (Sync Service -> RabbitMQ -> Responder nodes).
3. Coordination of distributed database user grants and connection pools.
4. Deployment complexity and distributed failure modes.

## Decision
Merge `ocsp-responder`, `ocsp-sync-service`, and `ocsp-admin-api` into a single modular monolith (`ocsp-app`) using Spring Modulith.
- Boundaries are organized into domain-oriented modules (`responder`, `status`, `signing`, `sync`, `admin`, `shared`).
- Each module exposes only its public API ports and encapsulates internals.
- Module boundaries and dependency directions are verified at build time via `ApplicationModules.of(Application.class).verify()` and ArchUnit rules.
- Cache invalidation occurs directly in-process (`ApplicationEventPublisher` / in-JVM method call) with zero network hops.

## Consequences
- Single container deployment with reduced memory footprint and operational simplicity.
- Near-zero latency for cache invalidation upon status updates.
- Clear structural boundaries preserved by compiler and architectural unit tests.
- React Console communicates with the same backend at `/api/v1/admin/`.

