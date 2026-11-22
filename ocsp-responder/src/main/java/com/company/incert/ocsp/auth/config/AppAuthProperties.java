package com.company.incert.ocsp.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Primary authentication mode selector ({@code app.auth.mode = SELF_MANAGEMENT | KEYCLOAK}).
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "app.auth")
public class AppAuthProperties {

    private String mode;

    public AuthenticationMode resolvedMode() {
        return AuthenticationMode.fromString(mode);
    }
}

