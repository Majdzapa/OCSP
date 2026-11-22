package com.company.incert.ocsp.auth.config;

/**
 * Single deployment authentication mode selected by {@code app.auth.mode}:
 * <ul>
 *   <li>{@link #SELF_MANAGEMENT}: App DB owns credentials, identity, and app profile.</li>
 *   <li>{@link #KEYCLOAK}: Keycloak owns credentials and identity; App DB holds a read-only
 *       identity replica (keyed by {@code external_id}) plus app-specific profile &amp; permissions.</li>
 * </ul>
 */
public enum AuthenticationMode {
    SELF_MANAGEMENT,
    KEYCLOAK;

    public boolean isKeycloak() {
        return this == KEYCLOAK;
    }

    public static AuthenticationMode fromString(String value) {
        if (value == null || value.isBlank()) {
            return SELF_MANAGEMENT;
        }
        String clean = value.trim().toUpperCase().replace("-", "_");
        if ("KEYCLOCK".equals(clean) || "KEYCLOAK".equals(clean)
                || "OIDC".equals(clean) || "OAUTH2".equals(clean)) {
            return KEYCLOAK;
        }
        return SELF_MANAGEMENT;
    }
}
