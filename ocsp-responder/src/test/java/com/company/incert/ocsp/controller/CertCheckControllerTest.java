package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.entity.CertificateStatus;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.service.CertificateStatusService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class CertCheckControllerTest {

    private CertificateStatusService statusService;
    private CertCheckController controller;

    @BeforeEach
    void setUp() {
        statusService = mock(CertificateStatusService.class);
        controller = new CertCheckController(statusService);
    }

    @Test
    void checkStatus_unknownSerial_returnsUnknownResponse() {
        when(statusService.findBySerialHex("deadbeef")).thenReturn(Optional.empty());

        ResponseEntity<CertCheckController.CertStatusResponse> response = controller.checkStatus("deadbeef");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().serialHex()).isEqualTo("deadbeef");
        assertThat(response.getBody().status()).isEqualTo("UNKNOWN");
        assertThat(response.getBody().renewalAvailable()).isFalse();
    }

    @Test
    void checkStatus_goodCertificate_returnsGoodStatus() {
        RevocationStatus status = RevocationStatus.builder()
                .serialNumber(new BigInteger("123456", 16).toByteArray())
                .status(CertificateStatus.GOOD)
                .build();
        when(statusService.findBySerialHex("123456")).thenReturn(Optional.of(status));

        ResponseEntity<CertCheckController.CertStatusResponse> response = controller.checkStatus("123456");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo("GOOD");
        assertThat(response.getBody().revocationReason()).isNull();
        assertThat(response.getBody().renewalAvailable()).isFalse();
    }

    @Test
    void checkStatus_revokedCertificate_returnsRevokedStatusWithReason() {
        Instant revokedAt = Instant.parse("2026-11-14T20:00:00Z");
        RevocationStatus status = RevocationStatus.builder()
                .serialNumber(new BigInteger("abcdef", 16).toByteArray())
                .status(CertificateStatus.REVOKED)
                .revocationTime(revokedAt)
                .revocationReason("KEY_COMPROMISE")
                .build();
        when(statusService.findBySerialHex("abcdef")).thenReturn(Optional.of(status));

        ResponseEntity<CertCheckController.CertStatusResponse> response = controller.checkStatus("abcdef");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().status()).isEqualTo("REVOKED");
        assertThat(response.getBody().revocationReason()).isEqualTo("KEY_COMPROMISE");
        assertThat(response.getBody().revocationTime()).isEqualTo(revokedAt.toString());
        assertThat(response.getBody().renewalAvailable()).isTrue();
    }
}

