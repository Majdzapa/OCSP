package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.service.CertificateStatusService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/v1/admin/cert-check")
@RequiredArgsConstructor
public class CertCheckController {

    private final CertificateStatusService statusService;

    public record CertStatusResponse(
        String serialHex,
        String status,
        String revocationTime,
        String revocationReason,
        boolean renewalAvailable
    ) {}

    @GetMapping("/{serialHex}")
    public ResponseEntity<CertStatusResponse> checkStatus(@PathVariable("serialHex") String serialHex) {
        Optional<RevocationStatus> opt = statusService.findBySerialHex(serialHex);
        if (opt.isEmpty()) {
            return ResponseEntity.ok(new CertStatusResponse(serialHex, "UNKNOWN", null, null, false));
        }
        RevocationStatus status = opt.get();
        return ResponseEntity.ok(new CertStatusResponse(
            status.serialNumberHex(),
            status.getStatus().name(),
            status.getRevocationTime() != null ? status.getRevocationTime().toString() : null,
            status.getRevocationReason(),
            status.getStatus() == com.company.incert.ocsp.entity.CertificateStatus.REVOKED
        ));
    }
}
