package com.company.incert.ocsp.sync;

import com.company.incert.ocsp.shared.CertificateStatusRecord;
import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.shared.domain.CertificateStatus;
import com.company.incert.ocsp.status.application.port.in.LookupStatusUseCase;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MariaDBContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.kafka.KafkaContainer;

import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@SpringBootTest
@ActiveProfiles("test")
@Testcontainers(disabledWithoutDocker = true)
class KafkaSyncIntegrationTest {

    @Container
    static MariaDBContainer<?> mariadb = new MariaDBContainer<>("mariadb:10.11")
        .withDatabaseName("ocsp")
        .withUsername("ocsp_app")
        .withPassword("changeme");

    @Container
    static KafkaContainer kafka = new KafkaContainer(
        DockerImageName.parse("apache/kafka-native:3.8.0").asCompatibleSubstituteFor("apache/kafka")
    );

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", mariadb::getJdbcUrl);
        registry.add("spring.datasource.username", () -> "root");
        registry.add("spring.datasource.password", mariadb::getPassword);
        registry.add("spring.kafka.bootstrap-servers", kafka::getBootstrapServers);
        registry.add("hsm.enabled", () -> "false");
    }

    @Autowired
    private KafkaTemplate<String, String> kafkaTemplate;

    @Autowired
    private LookupStatusUseCase statusLookup;

    @Test
    void shouldConsumeStatusChangeAndUpsertDatabase() throws Exception {
        String eventId = UUID.randomUUID().toString();
        HexFormat hex = HexFormat.of();
        byte[] issuerNameHash = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
        byte[] issuerKeyHash = new byte[]{21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40};
        byte[] serial = new byte[]{0x01, 0x02, 0x03};

        String json = String.format("""
            {
              "eventId": "%s",
              "eventType": "CertificateStatusChanged",
              "occurredAt": "%s",
              "issuerKeyHashHex": "%s",
              "issuerNameHashHex": "%s",
              "serialNumberHex": "%s",
              "status": "REVOKED",
              "revocationTime": "%s",
              "revocationReason": "KEY_COMPROMISE",
              "sequence": 1,
              "schemaVersion": 1
            }
            """,
            eventId,
            Instant.now(),
            hex.formatHex(issuerKeyHash),
            hex.formatHex(issuerNameHash),
            hex.formatHex(serial),
            Instant.now()
        );

        String kafkaKey = hex.formatHex(issuerKeyHash) + ":" + hex.formatHex(serial);
        kafkaTemplate.send("incert.certificate.status.v1", kafkaKey, json).get();

        CertId certId = new CertId(issuerNameHash, issuerKeyHash, serial);
        await().atMost(Duration.ofSeconds(15)).untilAsserted(() -> {
            Optional<CertificateStatusRecord> status = statusLookup.lookup(certId);
            assertThat(status).isPresent();
            assertThat(status.get().status()).isEqualTo(CertificateStatus.REVOKED);
            assertThat(status.get().sequence()).isEqualTo(1);
        });
    }

    @Test
    void shouldRoutePoisonPillToDlt() throws Exception {
        // Send malformed JSON
        kafkaTemplate.send("incert.certificate.status.v1", "bad-key", "{ NOT VALID JSON").get();

        // Check DLT topic
        java.util.Properties props = new java.util.Properties();
        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafka.getBootstrapServers());
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "dlt-verifier-" + UUID.randomUUID());
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");

        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(props)) {
            consumer.subscribe(Collections.singletonList("incert.certificate.status.v1.dlt"));
            await().atMost(Duration.ofSeconds(15)).untilAsserted(() -> {
                var records = consumer.poll(Duration.ofMillis(500));
                assertThat(records).isNotEmpty();
                ConsumerRecord<String, String> dltRecord = records.iterator().next();
                assertThat(dltRecord.value()).contains("NOT VALID JSON");
            });
        }
    }
}

