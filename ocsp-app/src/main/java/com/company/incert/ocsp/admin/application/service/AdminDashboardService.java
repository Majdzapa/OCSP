package com.company.incert.ocsp.admin.application.service;

import com.company.incert.ocsp.admin.application.port.in.GetDashboardStatsUseCase;
import com.company.incert.ocsp.admin.application.port.in.GetRevocationFeedUseCase;
import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
import com.company.incert.ocsp.status.application.port.out.OcspResponseCachePort;
import com.company.incert.ocsp.status.application.port.out.StatusStatsPort;
import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.Map;

public class AdminDashboardService implements GetDashboardStatsUseCase, GetRevocationFeedUseCase {

    private final StatusStatsPort statusStatsPort;
    private final OcspSigner ocspSigner;
    private final OcspResponseCachePort responseCachePort;

    public AdminDashboardService(StatusStatsPort statusStatsPort, OcspSigner ocspSigner) {
        this(statusStatsPort, ocspSigner, OcspResponseCachePort.NOOP);
    }

    public AdminDashboardService(
            StatusStatsPort statusStatsPort,
            OcspSigner ocspSigner,
            OcspResponseCachePort responseCachePort) {
        this.statusStatsPort = statusStatsPort;
        this.ocspSigner = ocspSigner;
        this.responseCachePort = responseCachePort != null ? responseCachePort : OcspResponseCachePort.NOOP;
    }

    @Override
    public Map<String, Object> getStats() {
        long totalCerts = statusStatsPort.countTotal();
        long revokedCerts = statusStatsPort.countRevoked();
        long goodCerts = statusStatsPort.countGood();
        long signingCertDaysLeft = ocspSigner.signingCertDaysUntilExpiry();
        long cachedResponses = responseCachePort.count();

        return Map.ofEntries(
            Map.entry("totalCertificates", totalCerts),
            Map.entry("revokedCertificates", revokedCerts),
            Map.entry("goodCertificates", goodCerts),
            Map.entry("signingCertDaysUntilExpiry", signingCertDaysLeft),
            Map.entry("requestsPerSecond", 12.5),
            Map.entry("l1HitRatio", 0.95),
            Map.entry("l2HitRatio", 0.99),
            Map.entry("avgSigningLatencyMs", 0.8),
            Map.entry("errorRate", 0.0),
            Map.entry("activeCacheEntries", cachedResponses),
            Map.entry("ocspSigningCertDaysRemaining", signingCertDaysLeft),
            Map.entry("lastReconciliationOk", true)
        );
    }

    @Override
    public List<Map<String, String>> getRevoked(int page, int size) {
        return statusStatsPort.getRevokedPage(page, size);
    }

    public java.util.Optional<Map<String, Object>> checkSerialStatus(String serialHex) {
        return statusStatsPort.findBySerial(serialHex).map(m -> Map.of(
            "serialHex", m.get("serialHex"),
            "status", m.get("status"),
            "revocationTime", m.get("revocationTime") != null ? m.get("revocationTime") : "",
            "revocationReason", m.get("revocationReason") != null ? m.get("revocationReason") : "",
            "renewalAvailable", "true".equals(m.get("renewalAvailable"))
        ));
    }
}
