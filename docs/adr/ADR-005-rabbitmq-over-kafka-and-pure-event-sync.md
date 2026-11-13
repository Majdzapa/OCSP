# ADR-005: RabbitMQ Broker and Pure Asynchronous Event Synchronization

## Status
Accepted

## Context
Originally, the subsystem evaluated Apache Kafka for stream distribution and relied on periodic HTTP snapshot reconciliation (`ReconciliationService`) from the OCSP Responder to the KMS Simulator.

However:
1. Running a full Kafka broker and Zookeeper/KRaft introduced disproportionate operational overhead and memory footprint for private CA revocation rates.
2. Direct HTTP polling from the Responder to KMS violated separation of concerns and created a coupling point between the validation layer and the key management simulator.
3. The OCSP Responder should solely depend on its internal status database, populated strictly via asynchronous messages.

## Decision
1. **Adopt RabbitMQ (AMQP 0-9-1)** as the primary messaging backbone:
   - Direct exchange: `incert.certificate.status`
   - Durable worker queue: `ocsp.certificate.status` with DLX/DLQ handling (`ocsp.certificate.status.dlq`).
   - Standard AMQP acknowledgments and automatic dead-lettering for poison pills.
2. **Eliminate HTTP Reconciliation**:
   - Removed `ReconciliationService` and HTTP client calls from `ocsp-responder` to KMS.
   - Status changes are produced via KMS Transactional Outbox and consumed by `CertificateStatusListener`.
3. **Monotonic Sequence Enforcement**:
   - Each event carries a monotonic sequence counter per certificate serial number, ensuring out-of-order and duplicate event protection.

## Consequences
- **Positive**: Sub-100ms propagation latency from KMS mutation to OCSP status availability. Lower memory and CPU utilization. Total decoupling of Responder from KMS runtime.
- **Negative**: The responder relies entirely on the durable RabbitMQ queue for replay after extended outages.
