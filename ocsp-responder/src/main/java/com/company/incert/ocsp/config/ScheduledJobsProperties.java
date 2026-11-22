package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Single place that collects the configuration of every scheduled job of the OCSP responder,
 * bound from {@code ocsp.jobs.*} in {@code application*.yml} with no hardcoded values in code.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "ocsp.jobs")
public class ScheduledJobsProperties {

    private SigningCertValidity signingCertValidity = new SigningCertValidity();

    /** Daily check of the OCSP signing certificates' validity. */
    @Getter
    @Setter
    public static class SigningCertValidity {
        private boolean enabled;
        private String cron;
        private int alertThresholdDays;
    }
}
