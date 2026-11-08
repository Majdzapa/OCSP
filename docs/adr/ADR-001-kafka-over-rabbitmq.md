# ADR-001: Apache Kafka over RabbitMQ for Certificate Status Streaming

## Status
Accepted

## Context
The legacy architecture relied on RabbitMQ to distribute certificate issuance and revocation events from KMS to `ocsp-sync-service`, and to publish cache-invalidation messages between microservices.
However, RabbitMQ presented critical challenges:
1. **Per-Certificate Ordering Guarantees**: Under concurrent processing across consumers, RabbitMQ queues do not guarantee strict order per certificate entity without complex hashing plugins.
2. **Replay & Reconciliation**: RabbitMQ deletes messages upon acknowledgement. To rebuild or reconcile OCSP status caches, an independent HTTP reconciliation API had to be polled periodically.
3. **High-Throughput Durability**: For high-volume PKI events, Kafka's append-only partition log provides superior throughput, deterministic partitioning, and reliable replay.

## Decision
We replace RabbitMQ with Apache Kafka running in KRaft mode (no ZooKeeper dependency).
- Topic `incert.certificate.status.v1` with 6 partitions.
- Partition key = `issuerKeyHash:serialNumber`. This guarantees strict per-certificate ordering: all status transitions for a certificate land in the exact same partition in chronological order.
- Dead letter topic `incert.certificate.status.v1.dlt` for poison pills.
- Consumer group `ocsp-sync` with manual offset commits after database transactions.
- Sequence counter (`sequence`) in each event protects against out-of-order writes.

## Consequences
- Strict FIFO ordering per certificate is guaranteed by key-based partitioning.
- Consumers can rewind offsets to replay history or recover from catastrophic data corruption without external sync APIs.
- Simpler operations: KRaft mode eliminates ZooKeeper.
- Direct in-process cache invalidation replaces broker-based cache messages.

