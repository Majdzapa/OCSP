package com.company.incert.ocsp.admin.adapter.in;

import com.company.incert.ocsp.admin.application.service.AdminDashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class DashboardController {

    private final AdminDashboardService adminDashboardService;

    @GetMapping({"/dashboard", "/dashboard/stats"})
    public ResponseEntity<Map<String, Object>> getDashboard() {
        return ResponseEntity.ok(adminDashboardService.getStats());
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> getHealth() {
        Map<String, Object> stats = adminDashboardService.getStats();
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "signerDaysLeft", stats.get("signingCertDaysUntilExpiry")
        ));
    }

    @PostMapping("/reconcile")
    public ResponseEntity<Map<String, Object>> triggerReconciliation() {
        return ResponseEntity.ok(adminDashboardService.runReconciliation());
    }

    @GetMapping("/reconcile")
    public ResponseEntity<Map<String, Object>> getReconciliationStatus() {
        return ResponseEntity.ok(adminDashboardService.getReconciliationStatus());
    }
}
