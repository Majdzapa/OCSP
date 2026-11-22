package com.company.incert.ocsp.client.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/** Settings of the standalone OCSP client ({@code ocsp.client.*}), bound from {@code application*.yml}. */
@Getter
@Setter
@ConfigurationProperties(prefix = "ocsp.client")
public class OcspClientProperties {

    /** Responder URL used when a request does not specify one. */
    private String defaultResponderUrl;

    /** Optional directory holding a trusted CA certificate (intermediate-ca-cert.pem, ...). */
    private String pkiDir;

    /** HTTP connection timeout for outgoing OCSP requests. */
    private Duration connectTimeout;

    /** HTTP read timeout for outgoing OCSP requests. */
    private Duration readTimeout;
}
