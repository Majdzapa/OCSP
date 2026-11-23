package com.company.incert.ocsp.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Keycloak OIDC coordinates ({@code keycloak.*}), bound from {@code application*.yml}. */
@Getter
@Setter
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {

    private String authServerUrl;
    private String publicUrl;
    private String realm;
    private String clientId;
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
