package com.company.incert.ocsp.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Built-in admin credentials ({@code admin.*}), bound from {@code application*.yml}. */
@Getter
@Setter
@ConfigurationProperties(prefix = "admin")
public class AdminProperties {

    private String username;
    private String password;
}
