package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.service.OcspResponderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "OCSP Protocol", description = "RFC 6960 Online Certificate Status Protocol binary DER and base64url endpoints")
public class OcspResponderController {

    private static final String OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request";
    private static final String OCSP_RESPONSE_CONTENT_TYPE = "application/ocsp-response";

    private final OcspResponderService responderService;

    @Operation(
        summary = "Submit OCSP Request (POST)",
        description = "Standard RFC 6960 POST method. Consumes binary ASN.1 DER-encoded OCSPRequest and returns DER-encoded OCSPResponse signed dynamically via SoftHSM2 PKCS#11."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "OCSP response generated successfully",
                content = @Content(mediaType = "application/ocsp-response", schema = @Schema(type = "string", format = "binary"))),
        @ApiResponse(responseCode = "500", description = "Internal responder or signing error")
    })
    @PostMapping(consumes = OCSP_REQUEST_CONTENT_TYPE, produces = OCSP_RESPONSE_CONTENT_TYPE)
    public ResponseEntity<byte[]> handlePost(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Binary DER ASN.1 OCSPRequest", required = true)
            @RequestBody byte[] requestBody) {
        log.debug("POST /ocsp — {} bytes", requestBody != null ? requestBody.length : 0);
        return toResponse(responderService.handle(requestBody));
    }

    @Operation(
        summary = "Submit OCSP Request (GET)",
        description = "RFC 6960 GET method. Takes base64url-encoded ASN.1 DER OCSPRequest in the URL path and returns DER OCSPResponse."
    )
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "OCSP response generated successfully",
                content = @Content(mediaType = "application/ocsp-response", schema = @Schema(type = "string", format = "binary"))),
        @ApiResponse(responseCode = "400", description = "Malformed base64url request string"),
        @ApiResponse(responseCode = "500", description = "Internal responder or signing error")
    })
    @GetMapping(value = "/{base64Request}", produces = OCSP_RESPONSE_CONTENT_TYPE)
    public ResponseEntity<byte[]> handleGet(
            @Parameter(description = "URL-safe Base64 encoded DER OCSPRequest", required = true)
            @PathVariable("base64Request") String base64Request) {
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

