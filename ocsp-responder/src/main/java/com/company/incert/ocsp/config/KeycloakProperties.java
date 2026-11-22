package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Keycloak coordinates ({@code keycloak.*}). */
@Getter
@Setter
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {

    private String authServerUrl = "http://localhost:8081";
    /** Browser-facing base URL used for the login redirect; falls back to {@link #authServerUrl}. */
    private String publicUrl;
    private String realm = "incert";
    private String clientId = "ocsp-console";
    private String jwkSetUri;
    private String issuerUri;

    public String effectivePublicUrl() {
        return publicUrl != null && !publicUrl.isBlank() ? publicUrl : authServerUrl;
    }

    public String effectiveJwkSetUri() {
        return jwkSetUri != null && !jwkSetUri.isBlank()
                ? jwkSetUri
                : authServerUrl + "/realms/" + realm + "/protocol/openid-connect/certs";
    }
}

