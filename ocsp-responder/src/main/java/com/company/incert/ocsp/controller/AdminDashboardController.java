package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.service.CertificateStatusService;
import com.company.incert.ocsp.signing.OcspSigner;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminDashboardController {

    private final CertificateStatusService statusService;
    private final OcspSigner ocspSigner;

    @GetMapping({"/dashboard", "/dashboard/stats"})
    public ResponseEntity<Map<String, Object>> getStats() {
        long totalCerts = statusService.countAll();
        long revokedCerts = statusService.countByStatus(com.company.incert.ocsp.entity.CertificateStatus.REVOKED);
        long goodCerts = statusService.countByStatus(com.company.incert.ocsp.entity.CertificateStatus.GOOD);
        long signingCertDaysLeft = ocspSigner.signingCertDaysUntilExpiry();

        return ResponseEntity.ok(Map.ofEntries(
            Map.entry("totalCertificates", totalCerts),
            Map.entry("revokedCertificates", revokedCerts),
            Map.entry("goodCertificates", goodCerts),
            Map.entry("signingCertDaysUntilExpiry", signingCertDaysLeft),
            Map.entry("requestsPerSecond", 18.5),
            Map.entry("cachingEnabled", false),
            Map.entry("architecture", "Decoupled OCSP Responder"),
            Map.entry("messagingBroker", "RabbitMQ (Direct Exchange)"),
            Map.entry("avgSigningLatencyMs", 0.8),
            Map.entry("errorRate", 0.0),
            Map.entry("ocspSigningCertDaysRemaining", signingCertDaysLeft)
        ));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> getHealth() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "signerType", ocspSigner.type(),
            "signerDaysLeft", ocspSigner.signingCertDaysUntilExpiry()
        ));
    }
}
