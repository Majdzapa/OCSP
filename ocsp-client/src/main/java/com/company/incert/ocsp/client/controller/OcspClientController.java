package com.company.incert.ocsp.client.controller;

import com.company.incert.ocsp.client.dto.OcspCheckRequest;
import com.company.incert.ocsp.client.dto.OcspCheckResult;
import com.company.incert.ocsp.client.service.OcspClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/client")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class OcspClientController {

    private final OcspClientService clientService;

    @Value("${ocsp.client.default-responder-url:http://localhost:8080/ocsp}")
    private String defaultResponderUrl;

    @PostMapping("/check")
    public ResponseEntity<OcspCheckResult> checkCertificate(@RequestBody OcspCheckRequest request) {
        OcspCheckResult result = clientService.check(request);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> getInfo() {
        return ResponseEntity.ok(Map.of(
            "service", "Incert OCSP Client & Testing Service",
            "version", "3.0.0",
            "defaultResponderUrl", defaultResponderUrl,
            "rfcCompliance", List.of("RFC 6960 (OCSP)", "RFC 8954 (Nonce Extension)")
        ));
    }

    @GetMapping("/presets")
    public ResponseEntity<List<Map<String, String>>> getPresets() {
        return ResponseEntity.ok(List.of(
            Map.of("label", "ee-01 (Expected: GOOD)", "serialHex", "00b59d41baf78afe0de1bbe7ae28c0450f"),
            Map.of("label", "ee-02 (Expected: REVOKED)", "serialHex", "008a5232e619344f2ebdb9b35f93e6a70d"),
            Map.of("label", "ee-03 (Expected: HOLD / GOOD)", "serialHex", "00dcd6e3751e8e68a43f3fc6561007e833")
        ));
    }
}
