package lu.incert.ocsp.status.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import lu.incert.ocsp.shared.config.OpenApiConfig;
import lu.incert.ocsp.status.entity.RevocationStatus;
import lu.incert.ocsp.status.service.CertificateStatusService;
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

import java.math.BigInteger;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/admin/cert-check")
@RequiredArgsConstructor
@Tag(name = "Certificate Check", description = "Direct certificate status lookup in the responder DB")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
public class CertCheckController {

    private final CertificateStatusService statusService;

    @Schema(description = "Certificate status inspection response")
    public record CertStatusResponse(
        @Schema(description = "Serial number hex", example = "008a5232e619344f2ebdb9b35f93e6a70d") String serialHex,
        @Schema(description = "Certificate status (GOOD, REVOKED, UNKNOWN)", example = "REVOKED") String status,
        @Schema(description = "Revocation timestamp if revoked") String revocationTime,
        @Schema(description = "Revocation reason if revoked", example = "KEY_COMPROMISE") String revocationReason,
        @Schema(description = "Whether renewal/replacement is available") boolean renewalAvailable,
        @Schema(description = "Diagnostic reason when status is UNKNOWN") String unknownReason,
        @Schema(description = "Stored RFC 6960 SHA-1 Issuer Name Hash (hex)") String issuerNameHashHex,
        @Schema(description = "Stored RFC 6960 SHA-1 Issuer Key Hash (hex)") String issuerKeyHashHex
    ) {}

    @Operation(summary = "Check certificate status by serial", description = "Looks up the current revocation status for a certificate serial in the local database")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Certificate status returned successfully",
                content = @Content(schema = @Schema(implementation = CertStatusResponse.class))),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/{serialHex}")
    @PreAuthorize("hasPermission(null, 'CERT_CHECK_READ')")
    public ResponseEntity<CertStatusResponse> checkStatus(
            @Parameter(description = "Hex-encoded serial number", example = "00b59d41baf78afe0de1bbe7ae28c0450f")
            @PathVariable("serialHex") String serialHex) {
        Optional<RevocationStatus> opt = statusService.findBySerialHex(serialHex);
        if (opt.isEmpty()) {
            String reason = diagnoseUnknownInDb(serialHex);
            return ResponseEntity.ok(new CertStatusResponse(serialHex, "UNKNOWN", null, null, false, reason, null, null));
        }
        RevocationStatus status = opt.get();
        HexFormat hex = HexFormat.of();
        String nameHashHex = status.getIssuerNameHash() != null ? hex.formatHex(status.getIssuerNameHash()) : null;
        String keyHashHex = status.getIssuerKeyHash() != null ? hex.formatHex(status.getIssuerKeyHash()) : null;
        String reason = status.getStatus() == lu.incert.ocsp.status.entity.CertificateStatus.UNKNOWN
                ? "Certificate row exists in OCSP database, and its stored status is explicitly UNKNOWN."
                : null;
        return ResponseEntity.ok(new CertStatusResponse(
            status.serialNumberHex(),
            status.getStatus().name(),
            status.getRevocationTime() != null ? status.getRevocationTime().toString() : null,
            status.getRevocationReason(),
            status.getStatus() == lu.incert.ocsp.status.entity.CertificateStatus.REVOKED,
            reason,
            nameHashHex,
            keyHashHex
        ));
    }

    private String diagnoseUnknownInDb(String rawInput) {
        String trimmed = rawInput != null ? rawInput.trim() : "";
        if (trimmed.matches("^[0-9]+$")) {
            try {
                BigInteger asDec = new BigInteger(trimmed, 10);
                List<RevocationStatus> decMatches = statusService.findAllBySerialBytes(asDec.toByteArray());
                if (!decMatches.isEmpty()) {
                    String hexSerial = HexFormat.of().formatHex(asDec.toByteArray());
                    return "Input '" + trimmed + "' was parsed as hexadecimal, which is not in OCSP DB — however, decimal "
                            + trimmed + " (hex: " + hexSerial + ") WAS found in OCSP DB (status: "
                            + decMatches.get(0).getStatus() + "). Enter the hex serial '" + hexSerial + "'.";
                }
            } catch (Exception ignored) {}
        }
        long total = statusService.countAll();
        if (total == 0) {
            return "OCSP database (revocation_status) is empty (0 synced certificates). Verify KMS published CertificateStatusChanged events to RabbitMQ.";
        }
        return "Serial '" + trimmed + "' is not found among the " + total
                + " certificate(s) in OCSP database (revocation_status). Check KMS Outbox or RabbitMQ Inbox Audit to verify synchronization.";
    }
}
