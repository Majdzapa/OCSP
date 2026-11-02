package com.company.ocsp.responder.controller;

import com.company.ocsp.responder.service.OcspProcessingService;
import io.micrometer.core.annotation.Timed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;

/**
 * Public OCSP endpoint — RFC 6960 §A.1.
 *
 * <p>Supports both request methods defined in the RFC:
 * <ul>
 *   <li>{@code POST /ocsp} — DER-encoded {@code OCSPRequest} in the request body.
 *   <li>{@code GET /ocsp/{base64url}} — URL-safe Base64-encoded request path segment,
 *       enabling HTTP-level caching / CDN acceleration for repeated identical requests.
 * </ul>
 *
 * <p>Content-Type for both request and response is
 * {@code application/ocsp-request} / {@code application/ocsp-response} as per RFC 6960.
 *
 * <p>This controller is intentionally stateless — all state lives in
 * {@link OcspProcessingService}, the cache, and MariaDB.  It can be deployed
 * behind any load balancer without affinity requirements.
 */
@Slf4j
@RestController
@RequestMapping("/ocsp")
@RequiredArgsConstructor
public class OcspController {

    /** MIME type for OCSP requests, per RFC 6960 §A.1. */
    private static final String OCSP_REQUEST_CONTENT_TYPE  = "application/ocsp-request";

    /** MIME type for OCSP responses, per RFC 6960 §A.1. */
    private static final String OCSP_RESPONSE_CONTENT_TYPE = "application/ocsp-response";

    private final OcspProcessingService processingService;

    /**
     * HTTP POST variant — body carries the DER-encoded OCSPRequest.
     *
     * <p>Per RFC 6960 §A.1: requests MUST carry Content-Type
     * {@code application/ocsp-request}.
     *
     * @param requestBody raw DER bytes from the HTTP request body
     * @return 200 OK with DER-encoded OCSPResponse body
     */
    @PostMapping(
        consumes = OCSP_REQUEST_CONTENT_TYPE,
        produces = OCSP_RESPONSE_CONTENT_TYPE
    )
    @Timed(value = "ocsp.request", extraTags = {"method", "POST"})
    public ResponseEntity<byte[]> handlePost(@RequestBody byte[] requestBody) {
        log.debug("POST /ocsp — {} bytes", requestBody != null ? requestBody.length : 0);
        byte[] responseBytes = processingService.process(requestBody);
        return buildOcspResponse(responseBytes);
    }

    /**
     * HTTP GET variant — request encoded as URL-safe Base64 in the path.
     *
     * <p>Per RFC 6960 §A.1: {@code GET {url}/{url-encoding of base-64 encoding of OCSPRequest}}.
     * This form allows HTTP caches / CDNs to cache responses for identical requests.
     *
     * @param base64Request URL-safe Base64-encoded DER OCSPRequest
     * @return 200 OK with DER-encoded OCSPResponse body
     */
    @GetMapping(
        value = "/{base64Request}",
        produces = OCSP_RESPONSE_CONTENT_TYPE
    )
    @Timed(value = "ocsp.request", extraTags = {"method", "GET"})
    public ResponseEntity<byte[]> handleGet(
            @PathVariable("base64Request") String base64Request) {
        log.debug("GET /ocsp/{}", base64Request.length() > 40
            ? base64Request.substring(0, 40) + "..." : base64Request);
        byte[] requestBytes = Base64.getUrlDecoder().decode(base64Request);
        byte[] responseBytes = processingService.process(requestBytes);
        return buildOcspResponse(responseBytes);
    }

    // -------------------------------------------------------------------------

    private ResponseEntity<byte[]> buildOcspResponse(byte[] der) {
        if (der == null || der.length == 0) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType(OCSP_RESPONSE_CONTENT_TYPE))
            .body(der);
    }
}
