package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.OpenApiConfig;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.service.CertificateStatusService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.client.RestClient;

@RestController
@RequestMapping("/api/v1/admin/cert-check")
@RequiredArgsConstructor
@Tag(name = "Certificate Check", description = "Direct certificate status lookup in the responder DB")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.API_KEY_SCHEME)
public class CertCheckController {

    private final CertificateStatusService statusService;

    @Value("${kms.url:http://kms-simulator:8090}")
    private String kmsUrl;

    @Schema(description = "Certificate status inspection response")
    public record CertStatusResponse(
        @Schema(description = "Serial number hex", example = "008a5232e619344f2ebdb9b35f93e6a70d") String serialHex,
        @Schema(description = "Certificate status (GOOD, REVOKED, UNKNOWN)", example = "REVOKED") String status,
        @Schema(description = "Revocation timestamp if revoked") String revocationTime,
        @Schema(description = "Revocation reason if revoked", example = "KEY_COMPROMISE") String revocationReason,
        @Schema(description = "Whether renewal/replacement is available") boolean renewalAvailable
    ) {}

    @Schema(description = "Certificate renewal / reinstatement response")
    public record RenewRequestResponse(
        @Schema(description = "Unique renewal request ID") String requestId,
        @Schema(description = "Serial number hex") String serialHex,
        @Schema(description = "New KMS status") String kmsStatus,
        @Schema(description = "Updated validity end timestamp") String newNotAfter,
        @Schema(description = "Submission timestamp") String submittedAt
    ) {}

    @Operation(summary = "Check certificate status by serial", description = "Looks up the current revocation status for a certificate serial in the local database")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Certificate status returned successfully",
                content = @Content(schema = @Schema(implementation = CertStatusResponse.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/{serialHex}")
    public ResponseEntity<CertStatusResponse> checkStatus(
            @Parameter(description = "Hex-encoded serial number", example = "00b59d41baf78afe0de1bbe7ae28c0450f")
            @PathVariable("serialHex") String serialHex) {
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

    @Operation(summary = "Request certificate renewal / reinstatement",
               description = "Forwards a renewal / reinstatement request to the KMS Simulator and publishes the updated status via RabbitMQ")
    @PostMapping("/{serialHex}/renew-request")
    public ResponseEntity<RenewRequestResponse> requestRenewal(
            @Parameter(description = "Hex-encoded serial number")
            @PathVariable("serialHex") String serialHex,
            @RequestBody(required = false) Map<String, String> body) {
        RestClient.create(kmsUrl)
            .post()
            .uri("/kms/certificates/{serial}/status", serialHex)
            .body(Map.of("status", "GOOD"))
            .retrieve()
            .toBodilessEntity();

        Instant now = Instant.now();
        return ResponseEntity.ok(new RenewRequestResponse(
            "REQ-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(),
            serialHex,
            "GOOD (Reinstated via KMS)",
            now.plus(90, ChronoUnit.DAYS).toString(),
            now.toString()
        ));
    }
}
