package com.company.ocsp.responder.config;

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
 * RabbitMQ topology for the OCSP Responder.
 *
 * <p>The responder only <em>consumes</em> from the cache-invalidation queue;
 * it does not publish any domain events.  Queue declaration here is idempotent
 * and safe to repeat on restart.
 */
@Configuration
public class RabbitMqConfig {

    @Value("${ocsp.rabbitmq.cache-invalidation-queue:ocsp.cache.invalidate}")
    private String cacheInvalidationQueue;

    /**
     * Durable queue for cache-invalidation signals from the sync service.
     */
    @Bean
    public Queue cacheInvalidationQueue() {
        return QueueBuilder.durable(cacheInvalidationQueue).build();
    }

    /**
     * JSON message converter — messages are serialised as JSON by the sync service
     * and deserialised here as {@code Map<String, String>}.
     */
    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(jsonMessageConverter());
        return template;
    }

    @Bean
    public SimpleRabbitListenerContainerFactory rabbitListenerContainerFactory(
            ConnectionFactory connectionFactory) {
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        factory.setConnectionFactory(connectionFactory);
        factory.setMessageConverter(jsonMessageConverter());
        factory.setAcknowledgeMode(AcknowledgeMode.MANUAL);
        factory.setPrefetchCount(10);
        return factory;
    }
}
