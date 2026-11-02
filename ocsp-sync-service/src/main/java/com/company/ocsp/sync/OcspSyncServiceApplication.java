package com.company.ocsp.sync;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * OCSP Status Sync Service.
 *
 * <p>Consumes {@code CertificateIssued} and {@code CertificateRevoked} domain events
 * from RabbitMQ (published by the Incert KMS), writes revocation state into MariaDB,
 * and emits lightweight cache-invalidation signals so OCSP responder nodes can
 * proactively evict stale cached responses within the &lt;60 second SLA.
 *
 * <p>A periodic reconciliation job provides belt-and-braces defense against missed
 * events by comparing KMS revocation counts with the local MariaDB state.
 */
@SpringBootApplication
@EnableScheduling
public class OcspSyncServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(OcspSyncServiceApplication.class, args);
    }
}
