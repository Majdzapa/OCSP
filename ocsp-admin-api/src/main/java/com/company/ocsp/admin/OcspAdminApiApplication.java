package com.company.ocsp.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * OCSP Admin API — internal-only management REST API backing the React console.
 *
 * <p>Secured with OAuth2/OIDC (JWT bearer tokens from the company SSO).
 * Exposed only on the internal network, never alongside the public {@code /ocsp} endpoint.
 */
@SpringBootApplication
public class OcspAdminApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(OcspAdminApiApplication.class, args);
    }
}
