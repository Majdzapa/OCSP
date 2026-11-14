# ADR-008: RabbitMQ Strict Mutual TLS (mTLS) with Trusted Peer Verification

## Status
Accepted

## Context
The Incert OCSP Subsystem relies on an asynchronous event broker (RabbitMQ) to broadcast certificate status changes from the KMS Simulator (and production CAs) to the OCSP Responder transactional inbox.

In a zero-trust enterprise environment, messaging brokers must guarantee confidentiality, data integrity, and mutual authentication of all publishers and consumers. Plaintext AMQP (port 5672) is vulnerable to interception, tampering, and unauthorized message injection.

## Decision
1. **Plaintext Listener Disabled**:
   - `listeners.tcp = none` is configured in `rabbitmq.conf` to completely disable the unencrypted port 5672.
2. **Strict Mutual TLS (mTLS) Listener**:
   - The broker listens exclusively on AMQPS port 5671 (`listeners.ssl.default = 5671`).
   - Mutual TLS authentication is enforced:
     ```ini
     ssl_options.verify               = verify_peer
     ssl_options.fail_if_no_peer_cert = true
     ssl_options.versions.1           = tlsv1.3
     ssl_options.versions.2           = tlsv1.2
     ```
3. **Dedicated PKI for Message Bus**:
   - Dedicated CA (`CN=Incert-RabbitMQ-CA, O=Incert, C=FR`).
   - Server certificate with SANs (`DNS:rabbitmq, DNS:localhost, IP:127.0.0.1`).
   - Client certificate (`CN=rabbitmq-client`) bundled into PKCS#12 keystore and truststore.
4. **Client-Side Configuration**:
   - Both `kms-simulator` and `ocsp-responder` use Spring Boot 4 AMQP SSL properties (`spring.rabbitmq.ssl.*`) with PKCS#12 keystore (`client-keystore.p12`) and truststore (`client-truststore.p12`).
5. **Rejection of Untrusted Connections**:
   - Any client without a client certificate triggers `SERVER ALERT: Fatal - Certificate required`.
   - Any client presenting an untrusted certificate triggers `SERVER ALERT: Fatal - Unknown CA`.

## Consequences
- **Positive**: Zero plaintext communication over the wire. Only certified internal services can publish or consume revocation events.
- **Positive**: Automatic defense against rogue message injection and eavesdropping.
- **Negative**: Certificate lifecycle management required for broker and client identities.
