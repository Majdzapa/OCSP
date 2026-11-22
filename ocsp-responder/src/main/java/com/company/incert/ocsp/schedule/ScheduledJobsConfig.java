package com.company.incert.ocsp.schedule;

import com.company.incert.ocsp.auth.service.IdentityOutboxService;
import com.company.incert.ocsp.auth.service.KeycloakSyncService;
import com.company.incert.ocsp.signing.service.SigningCertificateValidityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Central configuration class under {@code config} that collects and triggers all
 * scheduled jobs in the OCSP responder subsystem.
 * <p>
 * Job parameters and cron schedules are bound via {@link ScheduledJobsProperties}
 * ({@code ocsp.jobs.*} in {@code application*.yml}).
 */
@Slf4j
@Configuration
@EnableScheduling
@RequiredArgsConstructor
public class ScheduledJobsConfig {

    private final ScheduledJobsProperties jobsProperties;
    private final SigningCertificateValidityService signingCertificateValidityService;
    private final KeycloakSyncService keycloakSyncService;
    private final IdentityOutboxService identityOutboxService;

    /**
     * Daily scheduled job checking all registered signing certificates and raising alerts
     * for any certificate expiring within the configured threshold or already expired.
     */
    @Scheduled(cron = "${ocsp.jobs.signing-cert-validity.cron}")
    public void runDailySigningCertificateValidityJob() {
        if (!jobsProperties.getSigningCertValidity().isEnabled()) {
            log.debug("Daily signing certificate validity job is disabled via configuration");
            return;
        }
        signingCertificateValidityService.runDailyValidityCheck();
    }

    /**
     * Nightly reconciliation job (KEYCLOAK mode) syncing users from the Keycloak Admin API
     * into the local read-only identity replica.
     */
    @Scheduled(cron = "${ocsp.jobs.keycloak-reconciliation.cron}")
    public void runKeycloakUserReconciliationJob() {
        if (!jobsProperties.getKeycloakReconciliation().isEnabled()) {
            return;
        }
        try {
            keycloakSyncService.reconcileAllFromKeycloak();
        } catch (Exception e) {
            log.warn("Nightly Keycloak user reconciliation failed: {}", e.getMessage());
        }
    }

    /**
     * Periodic retry of failed/pending {@code identity_outbox} operations.
     */
    @Scheduled(fixedDelayString = "${ocsp.jobs.identity-outbox-retry.fixed-delay-ms}")
    public void runIdentityOutboxRetryJob() {
        if (!jobsProperties.getIdentityOutboxRetry().isEnabled()) {
            return;
        }
        identityOutboxService.retryPending();
    }
}
