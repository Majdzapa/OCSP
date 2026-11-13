package com.company.incert.ocsp.messaging;

import com.company.incert.ocsp.entity.CertificateStatus;
import com.company.incert.ocsp.entity.InboxEvent;
import com.company.incert.ocsp.repository.InboxEventRepository;
import com.company.incert.ocsp.service.CertificateStatusService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CertificateStatusConsumerServiceTest {

    @Mock
    private CertificateStatusService statusService;

    @Mock
    private InboxEventRepository inboxRepository;

    private CertificateStatusConsumerService consumerService;
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @BeforeEach
    void setUp() {
        consumerService = new CertificateStatusConsumerService(statusService, inboxRepository, objectMapper);
    }

    @Test
    void shouldProcessNewEventAndRecordInInbox() throws Exception {
        CertificateStatusEvent event = new CertificateStatusEvent(
                "evt-100",
                Instant.now(),
                "issuerKeyHash",
                "issuerNameHash",
                "00a1b2c3",
                CertificateStatus.REVOKED,
                Instant.now(),
                "KEY_COMPROMISE",
                5L
        );
        String payload = objectMapper.writeValueAsString(event);

        when(inboxRepository.findByEventId("evt-100")).thenReturn(Optional.empty());
        when(inboxRepository.save(any(InboxEvent.class))).thenAnswer(i -> i.getArgument(0));
        when(statusService.applyStatusChange(any())).thenReturn(true);

        consumerService.consume(payload);

        verify(statusService).applyStatusChange(any(CertificateStatusEvent.class));

        ArgumentCaptor<InboxEvent> captor = ArgumentCaptor.forClass(InboxEvent.class);
        verify(inboxRepository, times(2)).save(captor.capture());

        InboxEvent processed = captor.getAllValues().get(1);
        assertThat(processed.getProcessingStatus()).isEqualTo("PROCESSED");
        assertThat(processed.getCertificateSerial()).isEqualTo("00a1b2c3");
    }

    @Test
    void shouldHandleDuplicateEventIdGracefully() throws Exception {
        CertificateStatusEvent event = new CertificateStatusEvent(
                "evt-dup",
                Instant.now(),
                "kHash",
                "nHash",
                "00112233",
                CertificateStatus.GOOD,
                null,
                null,
                1L
        );
        String payload = objectMapper.writeValueAsString(event);

        InboxEvent existing = InboxEvent.builder()
                .eventId("evt-dup")
                .processingStatus("PROCESSED")
                .build();

        when(inboxRepository.findByEventId("evt-dup")).thenReturn(Optional.of(existing));

        consumerService.consume(payload);

        verify(statusService, never()).applyStatusChange(any());
        verify(inboxRepository).save(argThat(i -> "DUPLICATE".equals(i.getProcessingStatus())));
    }
}
