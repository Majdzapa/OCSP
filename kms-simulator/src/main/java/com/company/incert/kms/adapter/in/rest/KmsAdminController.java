package com.company.incert.kms.adapter.in.rest;

import com.company.incert.kms.adapter.in.job.RevocationJobAdapter;
import com.company.incert.kms.application.port.in.ListCertificatesUseCase;
import com.company.incert.kms.application.port.in.RevokeCertificateUseCase;
import com.company.incert.kms.application.port.in.UnrevokeCertificateUseCase;
import com.company.incert.kms.application.service.RevocationService.CertificateNotFoundException;
import com.company.incert.kms.domain.Certificate;
import com.company.incert.kms.domain.RevocationReason;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Dev-only REST endpoints for manual KMS operations.
 * Active only under the 'dev' Spring profile.
 */
@Slf4j
@RestController
@RequestMapping("/kms")
@Profile("dev")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
@Tag(name = "KMS Certificate Management", description = "Endpoints for managing PKI certificate lifecycles, revocations, and outbox event triggers")
public class KmsAdminController {

    private final RevokeCertificateUseCase revokeUseCase;
    private final UnrevokeCertificateUseCase unrevokeUseCase;
    private final ListCertificatesUseCase listUseCase;
    private final RevocationJobAdapter revocationJob;

    @Operation(summary = "List all certificates", description = "Retrieves the complete inventory of managed certificates and their current statuses")
    @ApiResponse(responseCode = "200", description = "List of certificates retrieved successfully")
    @GetMapping("/certificates")
    public List<Certificate> listCertificates() {
        return listUseCase.listAll();
    }

    /** Full status snapshot, usable by an OCSP reconciliation job. */
    @Operation(summary = "Get certificate inventory snapshot", description = "Full status snapshot used for OCSP reconciliation and audit checks")
    @ApiResponse(responseCode = "200", description = "Snapshot retrieved successfully")
    @GetMapping("/snapshot")
    public List<Certificate> snapshot() {
        return listUseCase.listAll();
    }

    /**
     * Accepts serials in any hex form (e.g. openssl "-serial" output, with or without
     * a leading sign byte) and converts to the canonical DER-content-bytes hex encoding.
     */
    static String normalizeSerial(String serial) {
        String s = serial.toLowerCase().replace(":", "");
        if (s.startsWith("0x")) s = s.substring(2);
        return java.util.HexFormat.of().formatHex(new java.math.BigInteger(s, 16).toByteArray());
    }

    @Operation(summary = "Revoke certificate", description = "Revokes a certificate by serial number and publishes a status change event to RabbitMQ via the transactional outbox")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Certificate revoked successfully",
                content = @Content(schema = @Schema(implementation = Certificate.class))),
        @ApiResponse(responseCode = "400", description = "Invalid revocation reason"),
        @ApiResponse(responseCode = "404", description = "Certificate not found")
    })
    @PostMapping("/certificates/{serial}/revoke")
    public ResponseEntity<?> revoke(
            @Parameter(description = "Certificate serial number in hexadecimal format (e.g. 00b59d...)", example = "008a5232e619344f2ebdb9b35f93e6a70d")
            @PathVariable("serial") String serial,
            @Parameter(description = "Standard RFC 5280 revocation reason", example = "KEY_COMPROMISE")
            @RequestParam(value = "reason", defaultValue = "KEY_COMPROMISE") String reasonStr) {
        try {
            RevocationReason reason = RevocationReason.valueOf(
                    reasonStr.toUpperCase().replace("-", "_"));
            Certificate cert = revokeUseCase.revoke(normalizeSerial(serial), reason);
            return ResponseEntity.ok(cert);
        } catch (CertificateNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid reason: " + reasonStr));
        }
    }

    @Operation(summary = "Unrevoke certificate (removeFromCRL)", description = "Reinstates a certificate that was previously put on CERTIFICATE_HOLD status")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Certificate unrevoked successfully",
                content = @Content(schema = @Schema(implementation = Certificate.class))),
        @ApiResponse(responseCode = "400", description = "Certificate cannot be unrevoked (not on hold)"),
        @ApiResponse(responseCode = "404", description = "Certificate not found")
    })
    @PostMapping("/certificates/{serial}/unrevoke")
    public ResponseEntity<?> unrevoke(
            @Parameter(description = "Certificate serial number in hexadecimal format", example = "00dcd6e3751e8e68a43f3fc6561007e833")
            @PathVariable("serial") String serial) {
        try {
            Certificate cert = unrevokeUseCase.unrevoke(normalizeSerial(serial));
            return ResponseEntity.ok(cert);
        } catch (CertificateNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Trigger revocation job immediately", description = "Forces immediate execution of the background revocation simulation job")
    @ApiResponse(responseCode = "200", description = "Revocation job triggered")
    @PostMapping("/jobs/revocation/run")
    public ResponseEntity<?> triggerRevocationJob() {
        revocationJob.runNow();
        return ResponseEntity.ok(Map.of("status", "triggered"));
    }
}
