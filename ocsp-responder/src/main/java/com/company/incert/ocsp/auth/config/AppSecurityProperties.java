package com.company.incert.ocsp.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/** Login TLS flag and CORS ({@code security.*}), bound from {@code application*.yml}. */
@Getter
@Setter
@ConfigurationProperties(prefix = "security")
public class AppSecurityProperties {

    private Tls tls = new Tls();
    private Cors cors = new Cors();

    @Getter
    @Setter
    public static class Tls {
        private boolean enabled;
        private boolean clientCertAuthEnabled;
    }

    @Getter
    @Setter
    public static class Cors {
        private List<String> allowedOrigins = new ArrayList<>();
    }
}
