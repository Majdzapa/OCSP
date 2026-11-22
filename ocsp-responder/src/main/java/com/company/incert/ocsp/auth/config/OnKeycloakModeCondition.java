package com.company.incert.ocsp.auth.config;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Matches when {@code app.auth.mode} resolves to {@link AuthenticationMode#KEYCLOAK}.
 */
public class OnKeycloakModeCondition implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String raw = context.getEnvironment().getProperty("app.auth.mode");
        return AuthenticationMode.fromString(raw).isKeycloak();
    }
}

