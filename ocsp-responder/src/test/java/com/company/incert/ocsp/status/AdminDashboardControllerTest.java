package com.company.incert.ocsp.status;


import com.company.incert.ocsp.status.controller.AdminDashboardController;
import com.company.incert.ocsp.auth.config.AppSecurityProperties;
import com.company.incert.ocsp.rabbitmq.config.RabbitMqTlsProperties;
import com.company.incert.ocsp.status.entity.CertificateStatus;
import com.company.incert.ocsp.status.service.CertificateStatusService;
import com.company.incert.ocsp.signing.hsm.OcspSigner;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class AdminDashboardControllerTest {

    private CertificateStatusService statusService;
    private OcspSigner ocspSigner;
    private AdminDashboardController controller;

    @BeforeEach
    void setUp() {
        statusService = mock(CertificateStatusService.class);
        ocspSigner = mock(OcspSigner.class);
        RabbitMqTlsProperties rabbitMqTls = new RabbitMqTlsProperties();
        rabbitMqTls.setEnabled(true);
        AppSecurityProperties securityProperties = new AppSecurityProperties();
        securityProperties.getTls().setEnabled(true);
        controller = new AdminDashboardController(statusService, ocspSigner, new SimpleMeterRegistry(),
                rabbitMqTls, securityProperties);
    }

    @Test
    void getStats_returnsAggregatedMetrics() {
        when(statusService.countAll()).thenReturn(42L);
        when(statusService.countByStatus(CertificateStatus.REVOKED)).thenReturn(5L);
        when(statusService.countByStatus(CertificateStatus.GOOD)).thenReturn(37L);
        when(ocspSigner.signingCertDaysUntilExpiry()).thenReturn(365L);

        ResponseEntity<Map<String, Object>> response = controller.getStats();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body.get("totalCertificates")).isEqualTo(42L);
        assertThat(body.get("revokedCertificates")).isEqualTo(5L);
        assertThat(body.get("goodCertificates")).isEqualTo(37L);
        assertThat(body.get("signingCertDaysUntilExpiry")).isEqualTo(365L);
        assertThat(body.get("tlsEnabled")).isEqualTo(true);
        assertThat(body.get("ocspLoginTlsEnabled")).isEqualTo(true);
        assertThat(body.get("messagingBroker")).isEqualTo("RabbitMQ (AMQPS / Strict mTLS)");
        // Real metrics from Micrometer (zero since no requests fired in test)
        assertThat(body).containsKey("avgSigningLatencyMs");
        assertThat(body).containsKey("requestsPerSecond");
        assertThat(body).containsKey("errorRate");
        assertThat(body).containsKey("errorCount");
    }
}

