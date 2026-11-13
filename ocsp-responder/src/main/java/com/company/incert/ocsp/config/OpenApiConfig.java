package com.company.incert.ocsp.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    public static final String BASIC_AUTH_SCHEME = "BasicAuth";
    public static final String API_KEY_SCHEME = "ApiKeyAuth";

    @Bean
    public OpenAPI ocspResponderOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Incert OCSP Responder API")
                        .description("High-performance, RFC 6960-compliant Online Certificate Status Protocol (OCSP) responder. " +
                                "Features hardware-backed dynamic cryptographic signing (SoftHSM2 PKCS#11), zero-caching direct DB lookups, " +
                                "RabbitMQ asynchronous revocation synchronization, and role-based Spring Security admin protection.")
                        .version("2.0.0")
                        .contact(new Contact()
                                .name("Incert PKI Architecture Team")
                                .email("pki-security@company.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")))
                .components(new Components()
                        .addSecuritySchemes(BASIC_AUTH_SCHEME, new SecurityScheme()
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("basic")
                                .description("Standard HTTP Basic Authentication for administrators (e.g. admin / changeme)"))
                        .addSecuritySchemes(API_KEY_SCHEME, new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("X-API-KEY")
                                .description("Administrative API Key header (e.g. incert-admin-secret-key)")));
    }
}
