package com.company.incert.ocsp.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Keycloak coordinates and least-privilege service account ({@code keycloak.*}), bound from {@code application*.yml}. */
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
    private String webhookSecret;
    private ServiceAccount serviceAccount = new ServiceAccount();

    public String effectivePublicUrl() {
        return publicUrl != null && !publicUrl.isBlank() ? publicUrl : authServerUrl;
    }

    public String effectiveJwkSetUri() {
        return jwkSetUri != null && !jwkSetUri.isBlank()
                ? jwkSetUri
                : authServerUrl + "/realms/" + realm + "/protocol/openid-connect/certs";
    }

    @Getter
    @Setter
    public static class ServiceAccount {
        private String clientId;
        private String clientSecret;
    }
}
