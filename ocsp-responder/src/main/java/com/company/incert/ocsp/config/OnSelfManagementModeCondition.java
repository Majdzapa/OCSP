package com.company.incert.ocsp.config;

import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Matches when {@code app.auth.mode} resolves to {@link AuthenticationMode#SELF_MANAGEMENT}.
 */
public class OnSelfManagementModeCondition implements Condition {
    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        String raw = context.getEnvironment().getProperty("app.auth.mode");
        return !AuthenticationMode.fromString(raw).isKeycloak();
    }
}

