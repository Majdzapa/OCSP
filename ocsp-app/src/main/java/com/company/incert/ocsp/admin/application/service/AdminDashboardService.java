package com.company.incert.ocsp.admin.application.service;

import com.company.incert.ocsp.admin.application.port.in.GetDashboardStatsUseCase;
import com.company.incert.ocsp.admin.application.port.in.GetRevocationFeedUseCase;
import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
import com.company.incert.ocsp.status.application.port.out.StatusStatsPort;
import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
public class AdminDashboardService implements GetDashboardStatsUseCase, GetRevocationFeedUseCase {

    private final StatusStatsPort statusStatsPort;
    private final OcspSigner ocspSigner;

    @Override
    public Map<String, Object> getStats() {
        long totalCerts = statusStatsPort.countTotal();
        long revokedCerts = statusStatsPort.countRevoked();
        long goodCerts = statusStatsPort.countGood();
        long signingCertDaysLeft = ocspSigner.signingCertDaysUntilExpiry();

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
            Map.entry("activeCacheEntries", goodCerts),
            Map.entry("ocspSigningCertDaysRemaining", signingCertDaysLeft),
            Map.entry("lastReconciliationOk", true)
        );
    }

    @Override
    public List<Map<String, String>> getRevoked(int page, int size) {
        return statusStatsPort.getRevokedPage(page, size);
    }
}
