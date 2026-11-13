package com.company.incert.ocsp.service;

import com.company.incert.ocsp.entity.CertificateStatus;
import com.company.incert.ocsp.entity.RevocationReason;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.messaging.CertificateStatusEvent;
import com.company.incert.ocsp.repository.RevocationStatusRepository;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
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
class CertificateStatusServiceTest {

    @Mock
    private RevocationStatusRepository repository;

    private CertificateStatusService service;

    @BeforeEach
    void setUp() {
        service = new CertificateStatusService(repository, new SimpleMeterRegistry());
    }

    @Test
    void shouldInsertNewCertificateStatus() {
        when(repository.findByCertId(any(), any(), any())).thenReturn(Optional.empty());

        CertificateStatusEvent event = new CertificateStatusEvent(
            "evt-1",
            Instant.now(),
            "aabbcc",
            "ddeeff",
            "123456",
            CertificateStatus.GOOD,
            null,
            null,
            1L
        );

        boolean applied = service.applyStatusChange(event);
        assertThat(applied).isTrue();

        ArgumentCaptor<RevocationStatus> captor = ArgumentCaptor.forClass(RevocationStatus.class);
        verify(repository).save(captor.capture());
        RevocationStatus saved = captor.getValue();
        assertThat(saved.getStatus()).isEqualTo(CertificateStatus.GOOD);
        assertThat(saved.getSequence()).isEqualTo(1L);
    }

    @Test
    void shouldUpdateWhenSequenceIsHigher() {
        RevocationStatus existing = RevocationStatus.builder()
            .issuerNameHash(new byte[]{1})
            .issuerKeyHash(new byte[]{2})
            .serialNumber(new byte[]{3})
            .status(CertificateStatus.GOOD)
            .sequence(1L)
            .build();

        when(repository.findByCertId(any(), any(), any())).thenReturn(Optional.of(existing));

        CertificateStatusEvent event = new CertificateStatusEvent(
            "evt-2",
            Instant.now(),
            "02",
            "01",
            "03",
            CertificateStatus.REVOKED,
            Instant.now(),
            RevocationReason.KEY_COMPROMISE.name(),
            2L
        );

        boolean applied = service.applyStatusChange(event);
        assertThat(applied).isTrue();
        assertThat(existing.getStatus()).isEqualTo(CertificateStatus.REVOKED);
        assertThat(existing.getRevocationReason()).isEqualTo(RevocationReason.KEY_COMPROMISE.name());
        assertThat(existing.getSequence()).isEqualTo(2L);
    }

    @Test
    void shouldIgnoreStaleEventWithLowerSequence() {
        RevocationStatus existing = RevocationStatus.builder()
            .issuerNameHash(new byte[]{1})
            .issuerKeyHash(new byte[]{2})
            .serialNumber(new byte[]{3})
            .status(CertificateStatus.REVOKED)
            .sequence(5L)
            .build();

        when(repository.findByCertId(any(), any(), any())).thenReturn(Optional.of(existing));

        CertificateStatusEvent staleEvent = new CertificateStatusEvent(
            "evt-old",
            Instant.now(),
            "02",
            "01",
            "03",
            CertificateStatus.GOOD,
            null,
            null,
            4L // Stale sequence
        );

        boolean applied = service.applyStatusChange(staleEvent);
        assertThat(applied).isFalse();
        verify(repository, never()).save(any());
        assertThat(existing.getStatus()).isEqualTo(CertificateStatus.REVOKED);
    }
}

