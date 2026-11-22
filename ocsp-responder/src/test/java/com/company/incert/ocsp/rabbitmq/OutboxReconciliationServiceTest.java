package com.company.incert.ocsp.rabbitmq;


import com.company.incert.ocsp.rabbitmq.service.OutboxReconciliationService;
import com.company.incert.ocsp.status.service.CertificateStatusService;
import com.company.incert.ocsp.rabbitmq.config.OcspRabbitMqProperties;
import com.company.incert.ocsp.status.entity.CertificateStatus;
import com.company.incert.ocsp.rabbitmq.entity.InboxEvent;
import com.company.incert.ocsp.status.entity.RevocationStatus;
import com.company.incert.ocsp.rabbitmq.messaging.OutboxManifestEvent;
import com.company.incert.ocsp.rabbitmq.repository.InboxEventRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.core.RabbitTemplate;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OutboxReconciliationServiceTest {

    @Mock
    private InboxEventRepository inboxRepository;

    @Mock
    private CertificateStatusService statusService;

    @Mock
    private RabbitTemplate rabbitTemplate;

    private ObjectMapper objectMapper;
    private OutboxReconciliationService service;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
        OcspRabbitMqProperties rabbitProperties = new OcspRabbitMqProperties();
        rabbitProperties.setExchange("incert.certificate.status");
        rabbitProperties.setReconciliationRequestRoutingKey("incert.reconciliation.request.v1");
        service = new OutboxReconciliationService(inboxRepository, statusService, rabbitTemplate, objectMapper,
                rabbitProperties);
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldReconcileOutboxManifestAgainstInboxAndTriggerRabbitMqReplay() throws Exception {
        OutboxManifestEvent manifest = new OutboxManifestEvent(
                "man-1",
                Instant.now(),
                2,
                3L,
                3L,
                0L,
                List.of("evt-1", "evt-2", "evt-missing"),
                List.of(
                        new OutboxManifestEvent.CertificateDigest("01a2", "GOOD", null, 0L, "evt-1"),
                        new OutboxManifestEvent.CertificateDigest("02b3", "REVOKED", "KEY_COMPROMISE", 1L, "evt-missing")
                )
        );
        service.onOutboxManifest(objectMapper.writeValueAsString(manifest));

        when(inboxRepository.findEventIdsByProcessingStatus(any(), any())).thenReturn(List.of("evt-2"));
        when(inboxRepository.countByProcessingStatus("FAILED")).thenReturn(1L);
        when(inboxRepository.findExistingEventIds(any())).thenReturn(List.of("evt-1", "evt-2"));
        when(inboxRepository.count()).thenReturn(2L);
        when(statusService.countAll()).thenReturn(1L);
        when(statusService.findBySerialNumbers(any())).thenReturn(List.of(
                RevocationStatus.builder()
                        .serialNumber(new BigInteger("01a2", 16).toByteArray())
                        .status(CertificateStatus.GOOD)
                        .sequence(0L)
                        .build()
        ));

        Map<String, Object> report = service.verifyReconciliation();

        assertThat(report.get("synchronized")).isEqualTo(false);
        assertThat(report.get("manifestReceived")).isEqualTo(true);
        assertThat(report.get("outboxTotalEvents")).isEqualTo(3L);
        assertThat((List<String>) report.get("missingInInboxEventIds")).containsExactly("evt-missing");
        assertThat((List<String>) report.get("failedInInboxEventIds")).containsExactly("evt-2");
        assertThat((List<String>) report.get("missingSerials")).containsExactly("02b3");
        assertThat(report.get("matchedCount")).isEqualTo(1);

        Map<String, Object> replayRes = service.triggerReplayViaRabbitMq();
        assertThat(replayRes.get("status")).isEqualTo("REPLAY_REQUESTED_VIA_RABBITMQ");

        ArgumentCaptor<Message> msgCaptor = ArgumentCaptor.forClass(Message.class);
        verify(rabbitTemplate).send(any(), any(), msgCaptor.capture());
        String sentJson = new String(msgCaptor.getValue().getBody(), StandardCharsets.UTF_8);
        assertThat(sentJson).contains("REPLAY_EVENTS").contains("evt-missing").contains("evt-2").contains("02b3");
    }
}

