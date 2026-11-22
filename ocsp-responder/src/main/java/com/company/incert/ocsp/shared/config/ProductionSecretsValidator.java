package com.company.incert.ocsp.shared.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Startup fail-fast validator that refuses to boot outside {@code dev}, {@code local}, or {@code test}
 * profiles if any required secret is missing or still set to a known development default.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ProductionSecretsValidator implements InitializingBean {

    private static final Set<String> NON_PROD_PROFILES = Set.of("dev", "local", "test");
    private static final Set<String> INSECURE_DEFAULTS = Set.of(
            "changeme",
            "guest",
            "rootpassword",
            "incert-keycloak-webhook-secret",
            "ocsp-user-sync-secret"
    );

    private final Environment environment;

    @Override
    public void afterPropertiesSet() {
        validate();
    }

    public void validate() {
        List<String> activeProfiles = Arrays.asList(environment.getActiveProfiles());
        boolean isNonProd = activeProfiles.stream().anyMatch(p -> NON_PROD_PROFILES.contains(p.toLowerCase()));
        if (isNonProd) {
            log.debug("Skipping strict production secrets validation for non-prod profiles: {}", activeProfiles);
            return;
        }

        List<String> violations = new ArrayList<>();
        checkSecret("spring.datasource.password", violations);
        checkSecret("spring.rabbitmq.password", violations);

        boolean rabbitmqTlsEnabled = Boolean.parseBoolean(environment.getProperty("rabbitmq.tls.enabled", "true"));
        if (rabbitmqTlsEnabled) {
            checkSecret("spring.rabbitmq.ssl.key-store-password", violations);
            checkSecret("spring.rabbitmq.ssl.trust-store-password", violations);
        }

        String authMode = environment.getProperty("app.auth.mode", "KEYCLOAK");
        boolean isKeycloak = "KEYCLOAK".equalsIgnoreCase(authMode) || "KEYCLOCK".equalsIgnoreCase(authMode);
        if (isKeycloak) {
            checkSecret("keycloak.webhook-secret", violations);
            checkSecret("keycloak.service-account.client-secret", violations);
        } else {
            checkSecret("admin.password", violations);
        }

        if (!violations.isEmpty()) {
            throw new IllegalStateException(
                    "Refusing to start in production profile(s) " + activeProfiles
                            + " with missing or insecure default secrets: " + String.join(", ", violations));
        }
        log.info("Production secrets validation passed for profiles {}", activeProfiles);
    }

    private void checkSecret(String propertyKey, List<String> violations) {
        String value = environment.getProperty(propertyKey);
        if (value == null || value.isBlank()) {
            violations.add(propertyKey + " (blank)");
        } else if (INSECURE_DEFAULTS.contains(value.trim().toLowerCase())) {
            violations.add(propertyKey + " (insecure dev default)");
        }
    }
}

