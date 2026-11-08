package com.company.incert.ocsp.admin.adapter.in;

import com.company.incert.ocsp.admin.application.service.AdminDashboardService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin/cert-check")
@RequiredArgsConstructor
public class CertCheckController {

    private final AdminDashboardService adminDashboardService;

    public record CertStatusResponse(
        String serialHex,
        String status,
        String revocationTime,
        String revocationReason,
        boolean renewalAvailable
    ) {}

    @GetMapping("/{serialHex}")
    public ResponseEntity<CertStatusResponse> checkStatus(@PathVariable("serialHex") String serialHex) {
        var opt = adminDashboardService.checkSerialStatus(serialHex);
        if (opt.isEmpty()) {
            return ResponseEntity.ok(new CertStatusResponse(
                serialHex, "UNKNOWN", null, null, false
            ));
        }
        var m = opt.get();
        String revTime = (String) m.get("revocationTime");
        String revReason = (String) m.get("revocationReason");
        return ResponseEntity.ok(new CertStatusResponse(
            (String) m.get("serialHex"),
            (String) m.get("status"),
            revTime != null && !revTime.isEmpty() ? revTime : null,
            revReason != null && !revReason.isEmpty() ? revReason : null,
            Boolean.TRUE.equals(m.get("renewalAvailable"))
        ));
    }

    public record OcspTestPayload(
        String serialHex,
        boolean includeNonce,
        String method
    ) {}

    @PostMapping("/test-request")
    public ResponseEntity<java.util.Map<String, Object>> testOcspRequest(@RequestBody OcspTestPayload payload) {
        return ResponseEntity.ok(adminDashboardService.simulateOcspRequest(
            payload.serialHex(),
            payload.includeNonce(),
            payload.method()
        ));
    }
}

