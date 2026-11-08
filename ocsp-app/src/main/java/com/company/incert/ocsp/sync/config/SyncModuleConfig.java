package com.company.incert.ocsp.sync.config;

import com.company.incert.ocsp.status.application.port.out.CacheEvictor;
import com.company.incert.ocsp.status.application.port.out.StatusWriter;
import com.company.incert.ocsp.sync.application.port.in.ApplyStatusChangeUseCase;
import com.company.incert.ocsp.sync.application.service.StatusChangeApplicationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.micrometer.core.instrument.MeterRegistry;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.*;
import org.springframework.kafka.listener.ContainerProperties;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.util.backoff.ExponentialBackOff;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class SyncModuleConfig {

    @Value("${spring.kafka.bootstrap-servers:localhost:9092}")
    private String bootstrapServers;

    @Bean
    public ApplyStatusChangeUseCase applyStatusChangeUseCase(
            StatusWriter statusWriter,
            CacheEvictor cacheEvictor,
            MeterRegistry meterRegistry) {
        return new StatusChangeApplicationService(statusWriter, cacheEvictor, meterRegistry);
    }

    @Bean
    public ProducerFactory<String, String> syncProducerFactory() {
        Map<String, Object> config = new HashMap<>();
        config.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        config.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        config.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        return new DefaultKafkaProducerFactory<>(config);
    }

    @Bean
    public KafkaTemplate<String, String> syncKafkaTemplate(ProducerFactory<String, String> syncProducerFactory) {
        return new KafkaTemplate<>(syncProducerFactory);
    }

    @Bean
    public ConsumerFactory<String, String> consumerFactory() {
        Map<String, Object> config = new HashMap<>();
        config.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        config.put(ConsumerConfig.GROUP_ID_CONFIG, "ocsp-sync");
        config.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        config.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        config.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, false);
        config.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        return new DefaultKafkaConsumerFactory<>(config);
    }

    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> ocspKafkaListenerContainerFactory(
            ConsumerFactory<String, String> consumerFactory,
            KafkaTemplate<String, String> syncKafkaTemplate) {
        ConcurrentKafkaListenerContainerFactory<String, String> factory =
            new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory);
        factory.getContainerProperties().setAckMode(ContainerProperties.AckMode.MANUAL);

        // Dead letter publishing recoverer → incert.certificate.status.v1.dlt
        DeadLetterPublishingRecoverer recoverer = new DeadLetterPublishingRecoverer(syncKafkaTemplate,
            (record, ex) -> new org.apache.kafka.common.TopicPartition("incert.certificate.status.v1.dlt", 0));

        // Exponential backoff: 500ms initial, multiplier 2.0, max 3 attempts
        ExponentialBackOff backoff = new ExponentialBackOff(500L, 2.0);
        backoff.setMaxElapsedTime(5000L);
        DefaultErrorHandler errorHandler = new DefaultErrorHandler(recoverer, backoff);
        factory.setCommonErrorHandler(errorHandler);

        return factory;
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper().registerModule(new JavaTimeModule());
    }
}

