package lu.incert.ocsp.schedule;

import lu.incert.ocsp.shared.config.ScheduledJobsProperties;
import lu.incert.ocsp.signing.service.SigningCertificateValidityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Central configuration class collecting and triggering all scheduled jobs in the OCSP responder.
 */
@Slf4j
@Configuration
@EnableScheduling
@RequiredArgsConstructor
public class ScheduledJobsConfig {

    private final ScheduledJobsProperties jobsProperties;
    private final SigningCertificateValidityService signingCertificateValidityService;

    @Scheduled(cron = "${ocsp.jobs.signing-cert-validity.cron}")
    public void runDailySigningCertificateValidityJob() {
        if (!jobsProperties.getSigningCertValidity().isEnabled()) {
            log.debug("Daily signing certificate validity job is disabled via configuration");
            return;
        }
        signingCertificateValidityService.runDailyValidityCheck();
    }
}
