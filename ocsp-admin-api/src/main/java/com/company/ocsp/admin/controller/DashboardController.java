package com.company.ocsp.admin.controller;

import com.company.ocsp.admin.dto.DashboardStatsDto;
import com.company.ocsp.admin.service.DashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller exposing dashboard statistics to the React admin console.
 *
 * <p>All endpoints require the {@code ROLE_OCSP_OPERATOR} or {@code ROLE_OCSP_ADMIN}
 * authority (mapped from JWT claims via the security configuration).
 *
 * <p>Base path: {@code /api/v1/admin/dashboard}
 */
@RestController
@RequestMapping("/api/v1/admin/dashboard")
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('OCSP_OPERATOR', 'OCSP_ADMIN')")
public class DashboardController {

    private final DashboardService dashboardService;

    /**
     * Returns aggregate request statistics, cache hit ratios, and per-node health.
     */
    @GetMapping("/stats")
    public ResponseEntity<DashboardStatsDto> getStats() {
        return ResponseEntity.ok(dashboardService.getStats());
    }
}
