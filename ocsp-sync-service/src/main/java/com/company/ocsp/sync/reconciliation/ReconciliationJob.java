package com.company.ocsp.sync.reconciliation;

import com.company.ocsp.sync.client.KmsClient;
import com.company.ocsp.sync.client.ReconciliationResponse;
import com.company.ocsp.sync.model.RevocationStatus;
import com.company.ocsp.sync.repository.RevocationStatusRepository;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Hourly reconciliation job — belt-and-braces defense against missed RabbitMQ events.
 *
 * <p>Compares the local count of {@code REVOKED} certificates in MariaDB against
 * the authoritative count returned by the KMS reconciliation endpoint.
 * Any discrepancy increments the {@code ocsp.reconciliation.discrepancy} gauge,
 * which Prometheus/Alertmanager uses to fire a PagerDuty alert.
 *
 * <p>This does NOT replace the event-driven path; it is a defense-in-depth
 * mechanism that catches:
 * <ul>
 *   <li>RabbitMQ node restarts with unconfirmed messages</li>
 *   <li>KMS publisher bugs</li>
 *   <li>Network partitions during event delivery</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ReconciliationJob {

    private final RevocationStatusRepository revocationStatusRepository;
    private final KmsClient                  kmsClient;
    private final MeterRegistry              meterRegistry;

    /**
     * Runs at the top of every hour by default.
     * Override with {@code ocsp.reconciliation.cron} in application.yml.
     */
    @Scheduled(cron = "${ocsp.reconciliation.cron:0 0 * * * *}")
    public void reconcile() {
        log.info("Starting OCSP reconciliation job");
        try {
            // Count locally-stored REVOKED certificates
            long localRevoked = revocationStatusRepository
                    .countByStatus(RevocationStatus.CertStatus.REVOKED);

            // Fetch authoritative count from the KMS
            ReconciliationResponse kmsResp = kmsClient.reconcile();
            long kmsRevoked = kmsResp.revokedCount();

            long discrepancy = Math.abs(kmsRevoked - localRevoked);

            // Publish discrepancy as a gauge so Prometheus can alert on it
            meterRegistry.gauge("ocsp.reconciliation.discrepancy", discrepancy);

            if (discrepancy == 0) {
                log.info("Reconciliation OK. revoked_local={} revoked_kms={}", localRevoked, kmsRevoked);
            } else {
                log.warn("Reconciliation discrepancy detected: kms={}, local={}, diff={}",
                        kmsRevoked, localRevoked, discrepancy);
            }

            meterRegistry.counter("ocsp.reconciliation.runs").increment();

        } catch (Exception e) {
            log.error("Reconciliation job failed: {}", e.getMessage(), e);
            meterRegistry.counter("ocsp.reconciliation.errors").increment();
        }
    }
}
