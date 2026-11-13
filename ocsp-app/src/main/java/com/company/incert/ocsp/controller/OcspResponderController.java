package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.service.OcspResponderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

/**
 * RFC 6960 HTTP endpoint for OCSP queries.
 * Standard POST (application/ocsp-request) and GET (/ocsp/{base64url}).
 */
@Slf4j
@RestController
@RequestMapping("/ocsp")
@RequiredArgsConstructor
public class OcspResponderController {

    private static final String OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request";
    private static final String OCSP_RESPONSE_CONTENT_TYPE = "application/ocsp-response";

    private final OcspResponderService responderService;

    @PostMapping(consumes = OCSP_REQUEST_CONTENT_TYPE, produces = OCSP_RESPONSE_CONTENT_TYPE)
    public ResponseEntity<byte[]> handlePost(@RequestBody byte[] requestBody) {
        log.debug("POST /ocsp — {} bytes", requestBody != null ? requestBody.length : 0);
        return toResponse(responderService.handle(requestBody));
    }

    @GetMapping(value = "/{base64Request}", produces = OCSP_RESPONSE_CONTENT_TYPE)
    public ResponseEntity<byte[]> handleGet(@PathVariable("base64Request") String base64Request) {
        log.debug("GET /ocsp/{}", base64Request.length() > 40 ? base64Request.substring(0, 40) + "..." : base64Request);
        try {
            byte[] derRequest = Base64.getUrlDecoder().decode(base64Request);
            return toResponse(responderService.handle(derRequest));
        } catch (IllegalArgumentException e) {
            log.warn("Invalid Base64 in GET /ocsp: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    private ResponseEntity<byte[]> toResponse(byte[] der) {
        if (der == null || der.length == 0) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(OCSP_RESPONSE_CONTENT_TYPE))
                .body(der);
    }
}

