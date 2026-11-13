package com.company.incert.ocsp.config;

/**
 * Authentication mode for the OCSP Responder subsystem:
 * <ul>
 *   <li>{@link #SELF_MANAGED}: Built-in administration authentication via HTTP Basic Auth
 *       and static API keys (X-API-KEY). No external identity provider required.</li>
 *   <li>{@link #KEYCLOCK}: Keycloak OAuth2 / OpenID Connect Resource Server. Validates
 *       Bearer JWT tokens issued by a Keycloak realm and extracts roles.</li>
 * </ul>
 */
public enum AuthenticationMode {
    SELF_MANAGED,
    KEYCLOCK,
    KEYCLOAK; // Alias for canonical spelling

    public boolean isKeycloak() {
        return this == KEYCLOCK || this == KEYCLOAK;
    }

    public static AuthenticationMode fromString(String value) {
        if (value == null || value.isBlank()) {
            return SELF_MANAGED;
        }
        String clean = value.trim().toUpperCase().replace("-", "_");
        if ("KEYCLOCK".equals(clean) || "KEYCLOAK".equals(clean) || "OIDC".equals(clean) || "OAUTH2".equals(clean)) {
            return KEYCLOCK;
        }
        return SELF_MANAGED;
    }
}

