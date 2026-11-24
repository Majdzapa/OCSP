package lu.incert.ocsp.client.controller;

import lu.incert.ocsp.client.config.OcspClientProperties;
import lu.incert.ocsp.client.dto.OcspCheckRequest;
import lu.incert.ocsp.client.dto.OcspCheckResult;
import lu.incert.ocsp.client.service.OcspClientService;
import lu.incert.ocsp.shared.config.OpenApiConfig;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/client")
@RequiredArgsConstructor
@Tag(name = "OCSP Client & Tester", description = "RFC 6960 OCSP validation, nonce echo verification, and test utilities")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
public class OcspClientController {

    private final OcspClientService clientService;

    private final OcspClientProperties clientProperties;

    @Operation(summary = "Perform OCSP validation check", description = "Constructs an RFC 6960 OCSPRequest (POST DER or GET base64url, with optional nonce), queries the responder, and cryptographically validates the response signature against the CA certificate")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Validation check completed with detailed diagnostic results",
                content = @Content(schema = @Schema(implementation = OcspCheckResult.class))),
        @ApiResponse(responseCode = "400", description = "Malformed check request")
    })
    @PostMapping("/check")
    @PreAuthorize("hasPermission(null, 'CERT_CHECK_READ')")
    public ResponseEntity<OcspCheckResult> checkCertificate(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Check options including serial, nonce preference, and transport method", required = true)
            @RequestBody OcspCheckRequest request) {
        OcspCheckResult result = clientService.check(request);
        return ResponseEntity.ok(result);
    }

    @Operation(summary = "Get client configuration info", description = "Returns service version, default responder URL, and RFC specifications supported")
    @ApiResponse(responseCode = "200", description = "Service metadata")
    @GetMapping("/info")
    @PreAuthorize("hasPermission(null, 'CERT_CHECK_READ')")
    public ResponseEntity<Map<String, Object>> getInfo() {
        return ResponseEntity.ok(Map.of(
            "service", "Incert OCSP Client & Testing Service",
            "version", "3.0.0",
            "defaultResponderUrl", clientProperties.getDefaultResponderUrl(),
            "rfcCompliance", List.of("RFC 6960 (OCSP)", "RFC 8954 (Nonce Extension)")
        ));
    }

    @Operation(summary = "Get certificate test presets", description = "Returns list of predefined test certificates (good, revoked, hold) for quick UI testing")
    @ApiResponse(responseCode = "200", description = "List of preset certificates")
    @GetMapping("/presets")
    @PreAuthorize("hasPermission(null, 'CERT_CHECK_READ')")
    public ResponseEntity<List<Map<String, String>>> getPresets() {
        return ResponseEntity.ok(List.of(
            Map.of("label", "ee-01 (Expected: GOOD)", "serialHex", "00b59d41baf78afe0de1bbe7ae28c0450f"),
            Map.of("label", "ee-02 (Expected: REVOKED)", "serialHex", "008a5232e619344f2ebdb9b35f93e6a70d"),
            Map.of("label", "ee-03 (Expected: HOLD / GOOD)", "serialHex", "00dcd6e3751e8e68a43f3fc6561007e833")
        ));
    }
}

