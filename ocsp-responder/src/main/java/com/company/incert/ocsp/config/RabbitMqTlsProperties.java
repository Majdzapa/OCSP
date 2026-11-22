package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Transport security of the RabbitMQ connection ({@code rabbitmq.tls.*}). */
@Getter
@Setter
@ConfigurationProperties(prefix = "rabbitmq.tls")
public class RabbitMqTlsProperties {

    /** Strict mTLS (AMQPS, port 5671) when true; plaintext AMQP (port 5672) when false. */
    private boolean enabled = true;
}

