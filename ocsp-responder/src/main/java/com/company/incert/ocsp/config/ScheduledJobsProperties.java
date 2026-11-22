package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Single place that collects the configuration of every scheduled job of the OCSP responder.
 *
 * <pre>
 * ocsp:
 *   jobs:
 *     signing-cert-validity:
 *       enabled: true
 *       cron: "0 0 0 * * *"
 *       alert-threshold-days: 3
 * </pre>
 *
 * Add a new nested block here (and a matching key in {@code application.yml}) whenever a new
 * {@code @Scheduled} job is introduced, so that all cron expressions live in one class.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "ocsp.jobs")
public class ScheduledJobsProperties {

    /** Fallback used when a configured threshold is not a positive number. */
    public static final int DEFAULT_ALERT_THRESHOLD_DAYS = 3;
    /** Every day at 00:00:00. */
    public static final String DEFAULT_VALIDITY_CRON = "0 0 0 * * *";

    private SigningCertValidity signingCertValidity = new SigningCertValidity();

    /** Daily check of the OCSP signing certificates' validity. */
    @Getter
    @Setter
    public static class SigningCertValidity {
        private boolean enabled = true;
        private String cron = DEFAULT_VALIDITY_CRON;
        private int alertThresholdDays = DEFAULT_ALERT_THRESHOLD_DAYS;

        public int effectiveAlertThresholdDays() {
            return alertThresholdDays > 0 ? alertThresholdDays : DEFAULT_ALERT_THRESHOLD_DAYS;
        }
    }
}

