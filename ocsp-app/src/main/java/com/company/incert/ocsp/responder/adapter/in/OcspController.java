package com.company.incert.ocsp.responder.adapter.in;

import com.company.incert.ocsp.responder.application.port.in.HandleOcspRequestUseCase;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

/**
 * RFC 6960 HTTP transport adapter.
 * Driving adapter: maps HTTP → HandleOcspRequestUseCase → HTTP.
 * No business logic here.
 */
@Slf4j
@RestController
@RequestMapping("/ocsp")
@RequiredArgsConstructor
public class OcspController {

    private static final String OCSP_REQUEST_CONTENT_TYPE  = "application/ocsp-request";
    private static final String OCSP_RESPONSE_CONTENT_TYPE = "application/ocsp-response";

    private final HandleOcspRequestUseCase handleOcspRequestUseCase;

    /** POST /ocsp — DER body (RFC 6960 §A.1) */
    @PostMapping(consumes = OCSP_REQUEST_CONTENT_TYPE, produces = OCSP_RESPONSE_CONTENT_TYPE)
    public ResponseEntity<byte[]> handlePost(@RequestBody byte[] requestBody) {
        log.debug("POST /ocsp — {} bytes", requestBody != null ? requestBody.length : 0);
        return toResponse(handleOcspRequestUseCase.handle(requestBody));
    }

    /** GET /ocsp/{base64Request} — URL-safe Base64 encoded request (RFC 6960 §A.1) */
    @GetMapping(value = "/{base64Request}", produces = OCSP_RESPONSE_CONTENT_TYPE)
    public ResponseEntity<byte[]> handleGet(@PathVariable("base64Request") String base64Request) {
        log.debug("GET /ocsp/{}", base64Request.length() > 40 ? base64Request.substring(0, 40) + "..." : base64Request);
        byte[] derRequest = Base64.getUrlDecoder().decode(base64Request);
        return toResponse(handleOcspRequestUseCase.handle(derRequest));
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

