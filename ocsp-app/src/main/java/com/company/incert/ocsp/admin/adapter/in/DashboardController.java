package com.company.incert.ocsp.admin.adapter.in;

import com.company.incert.ocsp.admin.application.port.in.GetDashboardStatsUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class DashboardController {

    private final GetDashboardStatsUseCase getDashboardStatsUseCase;

    @GetMapping({"/dashboard", "/dashboard/stats"})
    public ResponseEntity<Map<String, Object>> getDashboard() {
        return ResponseEntity.ok(getDashboardStatsUseCase.getStats());
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> getHealth() {
        Map<String, Object> stats = getDashboardStatsUseCase.getStats();
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "signerDaysLeft", stats.get("signingCertDaysUntilExpiry")
        ));
    }
}
