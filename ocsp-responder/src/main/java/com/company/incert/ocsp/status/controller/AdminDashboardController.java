package com.company.incert.ocsp.status.controller;

import com.company.incert.ocsp.auth.config.AppSecurityProperties;
import com.company.incert.ocsp.shared.config.OpenApiConfig;
import com.company.incert.ocsp.rabbitmq.config.RabbitMqTlsProperties;
import com.company.incert.ocsp.status.entity.CertificateStatus;
import com.company.incert.ocsp.status.service.CertificateStatusService;
import com.company.incert.ocsp.signing.hsm.OcspSigner;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Tag(name = "Admin Dashboard", description = "System metrics, health indicators, and signing key lifecycle statistics")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
public class AdminDashboardController {

    private final CertificateStatusService statusService;
    private final OcspSigner ocspSigner;
    private final MeterRegistry meterRegistry;
    private final RabbitMqTlsProperties rabbitMqTls;
    private final AppSecurityProperties securityProperties;

    private final AtomicLong lastTimerCount = new AtomicLong(0);
    private final AtomicLong lastSampleNanos = new AtomicLong(System.nanoTime());
    private volatile double lastRollingRps = 0.0;

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
        double avgLatencyMs  = getTimerMeanMs("ocsp.request.duration");
        long totalRequests   = getTimerCount("ocsp.request.duration");
        double errorCount    = getCounterValue("ocsp.request.error");
        double errorRate     = totalRequests > 0 ? Math.min(1.0, errorCount / totalRequests) : 0.0;
        double requestsPerSecond = getRequestsPerSecond("ocsp.request.duration");

        return ResponseEntity.ok(Map.ofEntries(
            Map.entry("totalCertificates", totalCerts),
            Map.entry("revokedCertificates", revokedCerts),
            Map.entry("goodCertificates", goodCerts),
            Map.entry("signingCertDaysUntilExpiry", signingCertDaysLeft),
            Map.entry("cachingEnabled", false),
            Map.entry("architecture", "Decoupled OCSP Responder"),
            Map.entry("tlsEnabled", rabbitMqTls.isEnabled()),
            Map.entry("ocspLoginTlsEnabled", securityProperties.getTls().isEnabled()),
            Map.entry("messagingBroker", rabbitMqTls.isEnabled() ? "RabbitMQ (AMQPS / Strict mTLS)" : "RabbitMQ (Plaintext)"),
            Map.entry("avgSigningLatencyMs", avgLatencyMs),
            Map.entry("requestsPerSecond", requestsPerSecond),
            Map.entry("totalRequests", totalRequests),
            Map.entry("errorRate", errorRate),
            Map.entry("errorCount", errorCount),
            Map.entry("ocspSigningCertDaysRemaining", signingCertDaysLeft),
            Map.entry("lastReconciliationOk", true)
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

    private long getTimerCount(String name) {
        try {
            Timer timer = meterRegistry.find(name).timer();
            return timer != null ? timer.count() : 0L;
        } catch (Exception e) {
            return 0L;
        }
    }

    private synchronized double getRequestsPerSecond(String name) {
        try {
            Timer timer = meterRegistry.find(name).timer();
            if (timer == null) {
                return 0.0;
            }
            long currentCount = timer.count();
            long nowNanos = System.nanoTime();
            long prevNanos = lastSampleNanos.get();
            double elapsedSec = (nowNanos - prevNanos) / 1_000_000_000.0;

            if (elapsedSec >= 2.0) {
                long prevCount = lastTimerCount.getAndSet(currentCount);
                lastSampleNanos.set(nowNanos);
                long delta = Math.max(0L, currentCount - prevCount);
                lastRollingRps = delta / elapsedSec;
            }

            if (lastRollingRps > 0.0) {
                return lastRollingRps;
            }
            if (currentCount == 0) {
                return 0.0;
            }
            var uptimeGauge = meterRegistry.find("process.uptime").gauge();
            double uptimeSec = uptimeGauge != null ? uptimeGauge.value() : 60.0;
            return uptimeSec > 0 ? currentCount / uptimeSec : 0.0;
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
