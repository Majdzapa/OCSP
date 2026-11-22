package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/** Authentication mode, login TLS flag and CORS ({@code security.*}). */
@Getter
@Setter
@ConfigurationProperties(prefix = "security")
public class AppSecurityProperties {

    /** SELF_MANAGED or KEYCLOAK (see {@link AuthenticationMode}). */
    private String authMode = "SELF_MANAGED";
    private Tls tls = new Tls();
    private Cors cors = new Cors();

    public AuthenticationMode authenticationMode() {
        return AuthenticationMode.fromString(authMode);
    }

    @Getter
    @Setter
    public static class Tls {
        private boolean enabled = true;
    }

    @Getter
    @Setter
    public static class Cors {
        private List<String> allowedOrigins = new ArrayList<>(
                List.of("http://localhost:3002", "http://localhost:3000", "http://localhost:5173"));
    }
}

