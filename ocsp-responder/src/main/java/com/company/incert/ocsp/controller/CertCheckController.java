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

import java.util.Optional;

@RestController
@RequestMapping("/api/v1/admin/cert-check")
@RequiredArgsConstructor
@Tag(name = "Certificate Check", description = "Direct certificate status lookup in the responder DB")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.API_KEY_SCHEME)
public class CertCheckController {

    private final CertificateStatusService statusService;

    @Schema(description = "Certificate status inspection response")
    public record CertStatusResponse(
        @Schema(description = "Serial number hex", example = "008a5232e619344f2ebdb9b35f93e6a70d") String serialHex,
        @Schema(description = "Certificate status (GOOD, REVOKED, UNKNOWN)", example = "REVOKED") String status,
        @Schema(description = "Revocation timestamp if revoked") String revocationTime,
        @Schema(description = "Revocation reason if revoked", example = "KEY_COMPROMISE") String revocationReason,
        @Schema(description = "Whether renewal/replacement is available") boolean renewalAvailable
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
}
