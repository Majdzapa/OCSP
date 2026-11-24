package lu.incert.ocsp.client.config;

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
    private String defaultResponderUrl = "http://localhost:8080/ocsp";

    /** Optional directory holding a trusted CA certificate (intermediate-ca-cert.pem, ...). */
    private String pkiDir = "./data/pki";

    /** HTTP connection timeout for outgoing OCSP requests. */
    private Duration connectTimeout = Duration.ofSeconds(5);

    /** HTTP read timeout for outgoing OCSP requests. */
    private Duration readTimeout = Duration.ofSeconds(10);
}
