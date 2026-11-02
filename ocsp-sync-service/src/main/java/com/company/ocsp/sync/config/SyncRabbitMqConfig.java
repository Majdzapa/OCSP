package com.company.ocsp.sync.config;

import org.springframework.amqp.core.*;
import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


/**
 * RabbitMQ topology declarations for the Sync Service.
 *
 * <p>Declares:
 * <ul>
 *   <li>{@code cert.events} topic exchange (published by KMS)
 *   <li>{@code ocsp.status.sync} — primary consumer queue
 *   <li>{@code ocsp.status.sync.dlq} — dead-letter queue for failed messages
 *   <li>{@code ocsp.internal} — internal direct exchange for cache-invalidation signals
 *   <li>{@code ocsp.cache.invalidate} — cache-invalidation queue (consumed by responders)
 * </ul>
 *
 * <p>All queues and exchanges are durable.  Queue declarations are idempotent.
 */
@Configuration
public class SyncRabbitMqConfig {

    @Value("${ocsp.rabbitmq.cert-events-exchange:cert.events}")
    private String certEventsExchange;

    @Value("${ocsp.rabbitmq.status-sync-queue:ocsp.status.sync}")
    private String statusSyncQueue;

    @Value("${ocsp.rabbitmq.status-sync-dlq:ocsp.status.sync.dlq}")
    private String statusSyncDlq;

    @Value("${ocsp.rabbitmq.cache-invalidation-exchange:ocsp.internal}")
    private String cacheInvalidationExchange;

    @Value("${ocsp.rabbitmq.cache-invalidation-queue:ocsp.cache.invalidate}")
    private String cacheInvalidationQueue;

    // ---- Exchanges ----

    @Bean
    public TopicExchange certEventsExchange() {
        return ExchangeBuilder.topicExchange(certEventsExchange).durable(true).build();
    }

    @Bean
    public DirectExchange cacheInvalidationExchange() {
        return ExchangeBuilder.directExchange(cacheInvalidationExchange).durable(true).build();
    }

    // ---- Queues ----

    @Bean
    public Queue statusSyncDlq() {
        return QueueBuilder.durable(statusSyncDlq).build();
    }

    @Bean
    public Queue statusSyncQueue() {
        return QueueBuilder.durable(statusSyncQueue)
            .withArgument("x-dead-letter-exchange", "")
            .withArgument("x-dead-letter-routing-key", statusSyncDlq)
            .build();
    }

    @Bean
    public Queue cacheInvalidationQueue() {
        return QueueBuilder.durable(cacheInvalidationQueue).build();
    }

    // ---- Bindings ----

    @Bean
    public Binding statusSyncBinding() {
        return BindingBuilder
            .bind(statusSyncQueue())
            .to(certEventsExchange())
            .with("cert.*");  // cert.issued, cert.revoked, cert.hold, cert.unrevoked
    }

    @Bean
    public Binding cacheInvalidationBinding() {
        return BindingBuilder
            .bind(cacheInvalidationQueue())
            .to(cacheInvalidationExchange())
            .with(cacheInvalidationQueue);
    }

    // ---- Infrastructure ----

    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(jsonMessageConverter());
        template.setMandatory(true);
        return template;
    }

    @Bean
    public SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory(
            ConnectionFactory connectionFactory) {
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        factory.setConnectionFactory(connectionFactory);
        factory.setMessageConverter(jsonMessageConverter());
        factory.setAcknowledgeMode(AcknowledgeMode.MANUAL);
        factory.setPrefetchCount(5);
        return factory;
    }

    // KMS HTTP client is configured in KmsClientConfig — see that class.
}
