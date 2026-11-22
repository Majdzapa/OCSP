package com.company.incert.ocsp.config;

import com.rabbitmq.client.ConnectionFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.DirectExchange;
import org.springframework.amqp.core.ExchangeBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.amqp.autoconfigure.ConnectionFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * RabbitMQ topology for certificate status events published by the KMS simulator.
 *
 * <pre>
 *  KMS outbox relay ──► exchange "incert.certificate.status" (direct, durable)
 *                         │ routing key "incert.certificate.status.v1"
 *                         ▼
 *                       queue "ocsp.certificate.status" (durable) ──► CertificateStatusListener
 *                         │ on failure after retries (dead-letter)
 *                         ▼
 *                       exchange "incert.certificate.status.dlx" ──► queue "ocsp.certificate.status.dlq"
 * </pre>
 *
 * The same topology is declared by the KMS simulator so that events published before this
 * application starts are retained in the durable queue. Declarations are idempotent, but the
 * arguments must stay identical on both sides.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class RabbitMqConfig {

    private final OcspRabbitMqProperties rabbit;
    private final RabbitMqTlsProperties tls;

    @Value("${spring.rabbitmq.port:5671}")
    private int configuredPort;

    @Bean
    public DirectExchange certificateStatusExchange() {
        return ExchangeBuilder.directExchange(rabbit.getExchange()).durable(true).build();
    }

    @Bean
    public Queue certificateStatusQueue() {
        return QueueBuilder.durable(rabbit.getQueue())
            .withArgument("x-dead-letter-exchange", rabbit.getDeadLetterExchange())
            .withArgument("x-dead-letter-routing-key", rabbit.getDeadLetterQueue())
            .build();
    }

    @Bean
    public Binding certificateStatusBinding() {
        return BindingBuilder.bind(certificateStatusQueue()).to(certificateStatusExchange()).with(rabbit.getRoutingKey());
    }

    @Bean
    public DirectExchange certificateStatusDeadLetterExchange() {
        return ExchangeBuilder.directExchange(rabbit.getDeadLetterExchange()).durable(true).build();
    }

    @Bean
    public Queue certificateStatusDeadLetterQueue() {
        return QueueBuilder.durable(rabbit.getDeadLetterQueue()).build();
    }

    @Bean
    public Binding certificateStatusDeadLetterBinding() {
        return BindingBuilder.bind(certificateStatusDeadLetterQueue())
            .to(certificateStatusDeadLetterExchange()).with(rabbit.getDeadLetterQueue());
    }

    @Bean
    public Queue reconciliationManifestQueue() {
        return QueueBuilder.durable(rabbit.getReconciliationManifestQueue()).build();
    }

    @Bean
    public Binding reconciliationManifestBinding() {
        return BindingBuilder.bind(reconciliationManifestQueue())
            .to(certificateStatusExchange()).with(rabbit.getReconciliationManifestRoutingKey());
    }

    @Bean
    public Queue reconciliationRequestQueue() {
        return QueueBuilder.durable(rabbit.getReconciliationRequestQueue()).build();
    }

    @Bean
    public Binding reconciliationRequestBinding() {
        return BindingBuilder.bind(reconciliationRequestQueue())
            .to(certificateStatusExchange()).with(rabbit.getReconciliationRequestRoutingKey());
    }

    @Bean
    public ConnectionFactoryCustomizer rabbitMqTlsPortCustomizer() {
        return (ConnectionFactory factory) -> {
            log.info("RabbitMQ Config: tlsEnabled={}, configuredPort={}", tls.isEnabled(), configuredPort);
            if (!tls.isEnabled() && configuredPort == 5671) {
                log.info("TLS is deactivated; switching RabbitMQ connection port to 5672 (plaintext)");
                factory.setPort(5672);
            }
        };
    }
}

