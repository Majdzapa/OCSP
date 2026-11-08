# ADR-004: Transactional Outbox Pattern for Certificate Events

## Status
Accepted

## Context
When the KMS updates certificate revocation status in its inventory database, it must simultaneously publish a domain event to Kafka. Dual-write patterns (writing to database then sending to message broker) suffer from failure modes where the DB commit succeeds but the message broker publish fails (or vice versa), leading to silent state divergence between KMS and OCSP.

## Decision
Implement the Transactional Outbox Pattern in `kms-simulator`:
1. Every certificate status mutation and corresponding `outbox_event` record are committed within the exact same database transaction in MariaDB (`kms` schema).
2. An asynchronous outbox relay component (`KafkaOutboxRelayAdapter`) polls unsent records from `outbox_event` on a short interval (500ms) and publishes them to Kafka with `enable.idempotence=true` and `acks=all`.
3. Once the Kafka broker acknowledges receipt, the outbox record is marked `sent=true`.

## Consequences
- Guaranteed at-least-once event delivery from KMS to Kafka without distributed two-phase commit transactions.
- Zero risk of DB/broker divergence during crashes or network partitions.
- At the consumer end, idempotent upserting (`source_event_id` constraint) and sequence checking (`sequence >= stored_sequence`) safeguard against duplicates and out-of-order deliveries.

