package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.entity.CertificateStatus;
import com.company.incert.ocsp.service.CertificateStatusService;
import com.company.incert.ocsp.signing.OcspSigner;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

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
        controller = new AdminDashboardController(statusService, ocspSigner, new SimpleMeterRegistry());

        ReflectionTestUtils.setField(controller, "tlsEnabled", true);
        ReflectionTestUtils.setField(controller, "ocspLoginTlsEnabled", true);
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

