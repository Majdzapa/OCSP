package lu.incert.ocsp.shared.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Single place collecting the configuration of scheduled jobs ({@code ocsp.jobs.*}).
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "ocsp.jobs")
public class ScheduledJobsProperties {

    private SigningCertValidity signingCertValidity = new SigningCertValidity();

    @Getter
    @Setter
    public static class SigningCertValidity {
        private boolean enabled;
        private String cron;
        private int alertThresholdDays;
    }
}
