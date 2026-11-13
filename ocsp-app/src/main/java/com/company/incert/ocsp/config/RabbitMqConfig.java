package com.company.incert.ocsp.config;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.DirectExchange;
import org.springframework.amqp.core.ExchangeBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.beans.factory.annotation.Value;
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
@Configuration
public class RabbitMqConfig {

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
}

