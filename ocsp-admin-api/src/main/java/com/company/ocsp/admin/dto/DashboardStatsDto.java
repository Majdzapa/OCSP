package com.company.ocsp.admin.dto;

import lombok.Builder;
import lombok.Data;

/**
 * Dashboard statistics DTO returned by {@code GET /api/v1/admin/dashboard/stats}.
 */
@Data
@Builder
public class DashboardStatsDto {

    /** Total OCSP requests per second (rolling 1-minute average). */
    private double requestsPerSecond;

    /** L1 cache hit ratio across all responder nodes (0.0–1.0). */
    private double l1HitRatio;

    /** L2 cache hit ratio across all responder nodes (0.0–1.0). */
    private double l2HitRatio;

    /** Average KMS signing latency in milliseconds. */
    private double avgSigningLatencyMs;

    /** Error rate (errors / total requests, rolling 1-minute). */
    private double errorRate;

    /** Number of currently-active L2 cache entries. */
    private long activeCacheEntries;

    /** Number of certificates currently in REVOKED status. */
    private long revokedCertificates;

    /** Days until the active OCSP signing certificate expires. */
    private long ocspSigningCertDaysRemaining;

    /** Whether the reconciliation job last run was successful. */
    private boolean lastReconciliationOk;
}
