package com.company.incert.ocsp.status;


import com.company.incert.ocsp.status.service.CertificateStatusService;
import com.company.incert.ocsp.status.entity.CertificateStatus;
import com.company.incert.ocsp.status.entity.RevocationReason;
import com.company.incert.ocsp.status.entity.RevocationStatus;
import com.company.incert.ocsp.rabbitmq.messaging.CertificateStatusEvent;
import com.company.incert.ocsp.status.repository.RevocationStatusRepository;
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

    @org.junit.jupiter.api.Test
    void parseSerial_highBitSet_keepsSignByte_matchingCertIdBigInteger() {
        java.math.BigInteger serial = new java.math.BigInteger("8602e6cd418b918c3a98b1e73c95b879", 16);
        assertThat(CertificateStatusService.parseSerial("008602e6cd418b918c3a98b1e73c95b879"))
            .isEqualTo(serial.toByteArray());
        assertThat(CertificateStatusService.parseSerial("8602e6cd418b918c3a98b1e73c95b879"))
            .isEqualTo(serial.toByteArray());
    }

    @Test
    void findByCertIdShouldReturnEmptyWithoutSerialFallbackWhenIssuerHashesDoNotMatch() {
        byte[] wrongNameHash = new byte[]{9, 9};
        byte[] wrongKeyHash = new byte[]{8, 8};
        byte[] serial = new byte[]{1, 2, 3};

        when(repository.findByCertId(wrongNameHash, wrongKeyHash, serial)).thenReturn(Optional.empty());

        Optional<RevocationStatus> result = service.findByCertId(wrongNameHash, wrongKeyHash, serial);

        assertThat(result).isEmpty();
        verify(repository, never()).findBySerialNumber(any());
    }

    @org.junit.jupiter.api.Test
    void parseSerial_highBitClear_dropsRedundantLeadingZero() {
        assertThat(CertificateStatusService.parseSerial("007f01")).isEqualTo(new byte[]{0x7f, 0x01});
    }
}

