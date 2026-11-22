package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/** OCSP response settings ({@code ocsp.responder.*}). */
@Getter
@Setter
@ConfigurationProperties(prefix = "ocsp.responder")
public class OcspResponderProperties {

    /** Validity window written into {@code nextUpdate} of every signed response. */
    private Duration nextUpdateWindow = Duration.ofHours(24);
}

