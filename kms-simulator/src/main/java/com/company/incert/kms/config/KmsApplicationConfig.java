package com.company.incert.kms.config;

import com.company.incert.kms.adapter.out.jpa.JpaCertificateRepositoryAdapter;
import com.company.incert.kms.adapter.out.jpa.JpaOutboxWriterAdapter;
import com.company.incert.kms.adapter.out.jpa.SpringDataCertificateRepository;
import com.company.incert.kms.adapter.out.jpa.SpringDataOutboxRepository;
import com.company.incert.kms.application.port.out.CertificateRepository;
import com.company.incert.kms.application.port.out.OutboxWriter;
import com.company.incert.kms.application.service.RevocationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration
@EnableScheduling
public class KmsApplicationConfig {

    @Bean
    public CertificateRepository certificateRepository(SpringDataCertificateRepository repo) {
        return new JpaCertificateRepositoryAdapter(repo);
    }

    @Bean
    public OutboxWriter outboxWriter(SpringDataOutboxRepository outboxRepo, ObjectMapper objectMapper) {
        return new JpaOutboxWriterAdapter(outboxRepo, objectMapper);
    }

    @Bean
    public RevocationService revocationService(CertificateRepository certRepo, OutboxWriter outboxWriter) {
        return new RevocationService(certRepo, outboxWriter);
    }

    @Bean
    public ObjectMapper objectMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }
}
