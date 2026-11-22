package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Built-in admin credentials ({@code admin.*}). */
@Getter
@Setter
@ConfigurationProperties(prefix = "admin")
public class AdminProperties {

    private String username = "admin";
    private String password = "changeme";
    private String apiKey = "incert-admin-secret-key";
}

