package com.company.incert.ocsp.config;

import com.rabbitmq.client.ConnectionFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.DirectExchange;
import org.springframework.amqp.core.ExchangeBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
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
public class RabbitMqConfig {

    @Value("${rabbitmq.tls.enabled:${spring.rabbitmq.ssl.enabled:true}}")
    private boolean tlsEnabled;

    @Value("${spring.rabbitmq.port:5671}")
    private int configuredPort;

    @Value("${ocsp.rabbitmq.exchange}")
    private String exchange;

    @Value("${ocsp.rabbitmq.queue}")
    private String queue;

    @Value("${ocsp.rabbitmq.routing-key}")
    private String routingKey;

    @Value("${ocsp.rabbitmq.dead-letter-exchange}")
    private String deadLetterExchange;

    @Value("${ocsp.rabbitmq.dead-letter-queue}")
    private String deadLetterQueue;

    @Value("${ocsp.rabbitmq.reconciliation-manifest-queue:ocsp.reconciliation.manifest}")
    private String reconciliationManifestQueue;

    @Value("${ocsp.rabbitmq.reconciliation-manifest-routing-key:incert.reconciliation.manifest.v1}")
    private String reconciliationManifestRoutingKey;

    @Value("${ocsp.rabbitmq.reconciliation-request-queue:kms.reconciliation.request}")
    private String reconciliationRequestQueue;

    @Value("${ocsp.rabbitmq.reconciliation-request-routing-key:incert.reconciliation.request.v1}")
    private String reconciliationRequestRoutingKey;

    @Bean
    public DirectExchange certificateStatusExchange() {
        return ExchangeBuilder.directExchange(exchange).durable(true).build();
    }

    @Bean
    public Queue certificateStatusQueue() {
        return QueueBuilder.durable(queue)
            .withArgument("x-dead-letter-exchange", deadLetterExchange)
            .withArgument("x-dead-letter-routing-key", deadLetterQueue)
            .build();
    }

    @Bean
    public Binding certificateStatusBinding() {
        return BindingBuilder.bind(certificateStatusQueue()).to(certificateStatusExchange()).with(routingKey);
    }

    @Bean
    public DirectExchange certificateStatusDeadLetterExchange() {
        return ExchangeBuilder.directExchange(deadLetterExchange).durable(true).build();
    }

    @Bean
    public Queue certificateStatusDeadLetterQueue() {
        return QueueBuilder.durable(deadLetterQueue).build();
    }

    @Bean
    public Binding certificateStatusDeadLetterBinding() {
        return BindingBuilder.bind(certificateStatusDeadLetterQueue())
            .to(certificateStatusDeadLetterExchange()).with(deadLetterQueue);
    }

    @Bean
    public Queue reconciliationManifestQueue() {
        return QueueBuilder.durable(reconciliationManifestQueue).build();
    }

    @Bean
    public Binding reconciliationManifestBinding() {
        return BindingBuilder.bind(reconciliationManifestQueue())
            .to(certificateStatusExchange()).with(reconciliationManifestRoutingKey);
    }

    @Bean
    public Queue reconciliationRequestQueue() {
        return QueueBuilder.durable(reconciliationRequestQueue).build();
    }

    @Bean
    public Binding reconciliationRequestBinding() {
        return BindingBuilder.bind(reconciliationRequestQueue())
            .to(certificateStatusExchange()).with(reconciliationRequestRoutingKey);
    }

    @Bean
    public ConnectionFactoryCustomizer rabbitMqTlsPortCustomizer() {
        return (ConnectionFactory factory) -> {
            log.info("RabbitMQ Config: tlsEnabled={}, configuredPort={}", tlsEnabled, configuredPort);
            if (!tlsEnabled && configuredPort == 5671) {
                log.info("TLS is deactivated; switching RabbitMQ connection port to 5672 (plaintext)");
                factory.setPort(5672);
            }
        };
    }
}

