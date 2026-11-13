package com.company.incert.ocsp.client.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI ocspClientOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Incert OCSP Client & Testing Service API")
                        .description("Standalone RFC 6960 / RFC 8954 OCSP client application. " +
                                "Constructs DER OCSP requests (POST / GET, with or without nonce extension), " +
                                "dispatches them to an OCSP responder, cryptographically validates response signatures against the CA certificate, " +
                                "verifies nonce echo integrity, and provides interactive diagnostic endpoints.")
                        .version("2.0.0")
                        .contact(new Contact()
                                .name("Incert PKI Architecture Team")
                                .email("pki-security@company.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")));
    }
}

