package com.company.incert.kms.config;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.DirectExchange;
import org.springframework.amqp.core.ExchangeBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitMqConfig {

    @Value("${kms.rabbitmq.exchange:incert.certificate.status}")
    private String exchange;

    @Value("${kms.rabbitmq.queue:ocsp.certificate.status}")
    private String queue;

    @Value("${kms.rabbitmq.routing-key:incert.certificate.status.v1}")
    private String routingKey;

    @Value("${kms.rabbitmq.dead-letter-exchange:incert.certificate.status.dlx}")
    private String deadLetterExchange;

    @Value("${kms.rabbitmq.dead-letter-queue:ocsp.certificate.status.dlq}")
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

