package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.OpenApiConfig;
import com.company.incert.ocsp.entity.CertificateStatus;
import com.company.incert.ocsp.service.CertificateStatusService;
import com.company.incert.ocsp.signing.OcspSigner;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Tag(name = "Admin Dashboard", description = "System metrics, health indicators, and signing key lifecycle statistics")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.API_KEY_SCHEME)
public class AdminDashboardController {

    private final CertificateStatusService statusService;
    private final OcspSigner ocspSigner;
    private final MeterRegistry meterRegistry;

    @Value("${rabbitmq.tls.enabled:${spring.rabbitmq.ssl.enabled:true}}")
    private boolean tlsEnabled;

    @Value("${security.tls.enabled:${auth.tls.enabled:${tls.enabled:true}}}")
    private boolean ocspLoginTlsEnabled;

    @Operation(summary = "Get admin dashboard statistics",
               description = "Retrieves live counts of good/revoked certificates, signing key expiry, and real-time Micrometer metrics")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Dashboard statistics returned successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized (missing or invalid credentials)")
    })
    @GetMapping({"/dashboard", "/dashboard/stats"})
    public ResponseEntity<Map<String, Object>> getStats() {
        long totalCerts  = statusService.countAll();
        long revokedCerts = statusService.countByStatus(CertificateStatus.REVOKED);
        long goodCerts   = statusService.countByStatus(CertificateStatus.GOOD);
        long signingCertDaysLeft = ocspSigner.signingCertDaysUntilExpiry();

        // Real metrics from Micrometer — 0 if not yet recorded
        double avgLatencyMs = getTimerMeanMs("ocsp.request.duration");
        double errorCount   = getCounterValue("ocsp.request.error");

        return ResponseEntity.ok(Map.ofEntries(
            Map.entry("totalCertificates", totalCerts),
            Map.entry("revokedCertificates", revokedCerts),
            Map.entry("goodCertificates", goodCerts),
            Map.entry("signingCertDaysUntilExpiry", signingCertDaysLeft),
            Map.entry("cachingEnabled", false),
            Map.entry("architecture", "Decoupled OCSP Responder"),
            Map.entry("tlsEnabled", tlsEnabled),
            Map.entry("ocspLoginTlsEnabled", ocspLoginTlsEnabled),
            Map.entry("messagingBroker", tlsEnabled ? "RabbitMQ (AMQPS / Strict mTLS)" : "RabbitMQ (Plaintext)"),
            Map.entry("avgSigningLatencyMs", avgLatencyMs),
            Map.entry("errorCount", errorCount),
            Map.entry("ocspSigningCertDaysRemaining", signingCertDaysLeft)
        ));
    }

    @Operation(summary = "Get responder subsystem health",
               description = "Returns health status of the PKCS#11 provider and token")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Health status returned successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> getHealth() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "signerType", ocspSigner.type(),
            "signerDaysLeft", ocspSigner.signingCertDaysUntilExpiry()
        ));
    }

    private double getTimerMeanMs(String name) {
        try {
            Timer timer = meterRegistry.find(name).timer();
            return timer != null ? timer.mean(TimeUnit.MILLISECONDS) : 0.0;
        } catch (Exception e) {
            return 0.0;
        }
    }

    private double getCounterValue(String name) {
        try {
            var counter = meterRegistry.find(name).counters();
            return counter.stream().mapToDouble(c -> c.count()).sum();
        } catch (Exception e) {
            return 0.0;
        }
    }
}
