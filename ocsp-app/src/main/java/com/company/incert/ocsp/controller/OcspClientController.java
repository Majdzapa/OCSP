package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.dto.OcspCheckRequest;
import com.company.incert.ocsp.dto.OcspCheckResult;
import com.company.incert.ocsp.service.OcspClientService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST API for the built-in RFC 6960 OCSP Client.
 * Builds requests, sends to the responder, verifies signatures, authorization, and nonces.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/client")
@RequiredArgsConstructor
public class OcspClientController {

    private final OcspClientService clientService;

    @PostMapping("/check")
    public ResponseEntity<OcspCheckResult> checkCertificate(@RequestBody OcspCheckRequest request) {
        log.info("OCSP Client check requested for serial={}, nonce={}", request.serialHex(), request.includeNonce());
        OcspCheckResult result = clientService.check(request);
        return ResponseEntity.ok(result);
    }
}

