package lu.incert.ocsp.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Primary authentication mode selector ({@code app.auth.mode = SELF_MANAGEMENT | KEYCLOAK})
 * and local Bearer JWT settings ({@code app.auth.jwt.*}).
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "app.auth")
public class AppAuthProperties {

    private String mode;
    private Jwt jwt = new Jwt();

    public AuthenticationMode resolvedMode() {
        return AuthenticationMode.fromString(mode);
    }

    @Getter
    @Setter
    public static class Jwt {
        private String secret;
        private String issuer = "incert-ocsp";
        private Duration expiration = Duration.ofHours(8);
    }
}
