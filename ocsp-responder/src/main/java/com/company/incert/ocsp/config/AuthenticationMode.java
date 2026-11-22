package com.company.incert.ocsp.config;

/**
 * Authentication mode for the OCSP Responder subsystem:
 * <ul>
 *   <li>{@link #SELF_MANAGED}: Built-in administration authentication via username and password
 *       (HTTP Basic Auth). No external identity provider required.</li>
 *   <li>{@link #KEYCLOAK}: Keycloak OAuth2 / OpenID Connect Resource Server. Validates
 *       Bearer JWT tokens issued by a Keycloak realm and extracts roles.</li>
 *   <li>{@link #KEYCLOCK}: Deprecated alias for {@link #KEYCLOAK} — kept for backward
 *       compatibility with existing configuration files and serialized values.</li>
 * </ul>
 */
public enum AuthenticationMode {
    SELF_MANAGED,
    /** Canonical spelling. */
    KEYCLOAK,
    /** @deprecated Use {@link #KEYCLOAK}. Retained for backward compatibility. */
    @Deprecated
    KEYCLOCK;

    public boolean isKeycloak() {
        return this == KEYCLOAK || this == KEYCLOCK;
    }

    public static AuthenticationMode fromString(String value) {
        if (value == null || value.isBlank()) {
            return SELF_MANAGED;
        }
        String clean = value.trim().toUpperCase().replace("-", "_");
        if ("KEYCLOCK".equals(clean) || "KEYCLOAK".equals(clean)
                || "OIDC".equals(clean) || "OAUTH2".equals(clean)) {
            return KEYCLOAK;
        }
        return SELF_MANAGED;
    }
}
