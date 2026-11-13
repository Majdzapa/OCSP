package com.company.incert.kms.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI kmsOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Incert KMS Simulator API")
                        .description("Event-driven Key Management System simulator for Incert Private CA. " +
                                "Manages certificate lifecycle, generates test PKI artifacts, " +
                                "and propagates status changes via transactional outbox to RabbitMQ.")
                        .version("2.0.0")
                        .contact(new Contact()
                                .name("Incert PKI Architecture Team")
                                .email("pki-security@company.com"))
                        .license(new License()
                                .name("Apache 2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")));
    }
}
