package com.company.ocsp.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * OCSP Dev Authorization Server.
 *
 * <p>A lightweight Spring Authorization Server used exclusively during local
 * development and integration testing.  It issues JWT Bearer tokens with
 * {@code OCSP_ADMIN} and {@code OCSP_OPERATOR} roles that the admin console
 * sends to the {@code ocsp-admin-api}.
 *
 * <p><b>Not for production use</b> — use your organisation's OIDC provider
 * (Keycloak, Okta, Azure AD) and set {@code OIDC_ISSUER_URI} accordingly.
 *
 * <p>Issuer: {@code http://localhost:9000}
 *
 * <h2>Getting a token (client credentials)</h2>
 * <pre>
 * curl -s -X POST http://localhost:9000/oauth2/token \
 *   -u "ocsp-console:secret" \
 *   -d "grant_type=client_credentials&scope=ocsp.admin" | jq .access_token
 * </pre>
 */
@SpringBootApplication
public class OcspAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(OcspAuthApplication.class, args);
    }
}
