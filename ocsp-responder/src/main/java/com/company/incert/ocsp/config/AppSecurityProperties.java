package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/** Authentication mode, login TLS flag and CORS ({@code security.*}), bound from {@code application*.yml}. */
@Getter
@Setter
@ConfigurationProperties(prefix = "security")
public class AppSecurityProperties {

    private String authMode;
    private Tls tls = new Tls();
    private Cors cors = new Cors();

    public AuthenticationMode authenticationMode() {
        return AuthenticationMode.fromString(authMode);
    }

    @Getter
    @Setter
    public static class Tls {
        private boolean enabled;
    }

    @Getter
    @Setter
    public static class Cors {
        private List<String> allowedOrigins = new ArrayList<>();
    }
}
