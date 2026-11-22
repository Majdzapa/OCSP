package com.company.incert.ocsp.config;

import com.company.incert.ocsp.service.SigningCertificateValidityService;
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
 * ({@code ocsp.jobs.*} in {@code application.yml}).
 */
@Slf4j
@Configuration
@EnableScheduling
@RequiredArgsConstructor
public class ScheduledJobsConfig {

    private final ScheduledJobsProperties jobsProperties;
    private final SigningCertificateValidityService signingCertificateValidityService;

    /**
     * Daily scheduled job (default: {@code 0 0 0 * * *}) checking all registered signing
     * certificates and raising alerts for any certificate expiring within the configured
     * threshold (default 3 days) or already expired.
     */
    @Scheduled(cron = "${ocsp.jobs.signing-cert-validity.cron:0 0 0 * * *}")
    public void runDailySigningCertificateValidityJob() {
        if (!jobsProperties.getSigningCertValidity().isEnabled()) {
            log.debug("Daily signing certificate validity job is disabled via configuration");
            return;
        }
        signingCertificateValidityService.runDailyValidityCheck();
    }
}
