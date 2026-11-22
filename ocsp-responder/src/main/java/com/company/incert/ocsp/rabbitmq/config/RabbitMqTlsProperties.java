package com.company.incert.ocsp.rabbitmq.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Transport security of the RabbitMQ connection ({@code rabbitmq.tls.*}), bound from {@code application*.yml}. */
@Getter
@Setter
@ConfigurationProperties(prefix = "rabbitmq.tls")
public class RabbitMqTlsProperties {

    private boolean enabled;
    private int tlsPort;
    private int plaintextPort;
}
