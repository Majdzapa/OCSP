package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.dto.OcspCheckRequest;
import com.company.incert.ocsp.dto.OcspCheckResult;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.service.CertificateStatusService;
import com.company.incert.ocsp.service.OcspClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/admin/cert-check")
@RequiredArgsConstructor
public class CertCheckController {

    private final CertificateStatusService statusService;
    private final OcspClientService ocspClientService;

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

    public record OcspTestPayload(
        String serialHex,
        boolean includeNonce,
        String method
    ) {}

    @PostMapping("/test-request")
    public ResponseEntity<Map<String, Object>> testOcspRequest(@RequestBody OcspTestPayload payload) {
        OcspCheckResult result = ocspClientService.check(new OcspCheckRequest(
            payload.serialHex(),
            null,
            null,
            payload.includeNonce(),
            payload.method(),
            null
        ));

        String cacheVerdict = payload.includeNonce()
            ? "NONCE_REQUEST (Dynamic RFC 6960 signing; cache disabled in monolith)"
            : "NONCE_FREE_REQUEST (Direct database query & dynamic HSM signing; cache disabled)";

        return ResponseEntity.ok(Map.ofEntries(
            Map.entry("serialHex", payload.serialHex() != null ? payload.serialHex() : ""),
            Map.entry("cacheKey", "N/A (Cache Disabled)"),
            Map.entry("method", result.method() != null ? result.method() : "POST"),
            Map.entry("includeNonce", result.includeNonce()),
            Map.entry("nonceSent", result.nonceSent() != null ? result.nonceSent() : ""),
            Map.entry("nonceEchoed", result.nonceEchoed() != null ? result.nonceEchoed() : ""),
            Map.entry("nonceMatched", result.nonceSent() != null && result.nonceSent().equalsIgnoreCase(result.nonceEchoed())),
            Map.entry("cacheVerdict", cacheVerdict),
            Map.entry("l2Hit", false),
            Map.entry("latencyMs", result.latencyMs()),
            Map.entry("certStatus", result.certStatus() != null ? result.certStatus() : "UNKNOWN"),
            Map.entry("revocationTime", result.revocationTime() != null ? result.revocationTime() : ""),
            Map.entry("revocationReason", result.revocationReason() != null ? result.revocationReason() : ""),
            Map.entry("thisUpdate", result.thisUpdate() != null ? result.thisUpdate() : ""),
            Map.entry("nextUpdate", result.nextUpdate() != null ? result.nextUpdate() : ""),
            Map.entry("responseSizeBytes", result.responseSizeBytes()),
            Map.entry("base64UrlPath", result.getRequestPath() != null ? result.getRequestPath() : ""),
            Map.entry("valid", result.valid()),
            Map.entry("checks", result.checks()),
            Map.entry("opensslCommand", payload.includeNonce()
                ? "openssl ocsp -issuer data/pki/intermediate-ca-cert.pem -cert data/pki/ee-01.pem -url http://localhost:8080/ocsp -nonce -CAfile data/pki/intermediate-ca-cert.pem"
                : "openssl ocsp -issuer data/pki/intermediate-ca-cert.pem -cert data/pki/ee-01.pem -url http://localhost:8080/ocsp -no_nonce -CAfile data/pki/intermediate-ca-cert.pem")
        ));
    }
}

