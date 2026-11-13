package com.company.incert.kms.controller;

import com.company.incert.kms.entity.Certificate;
import com.company.incert.kms.entity.CertificateStatus;
import com.company.incert.kms.entity.RevocationReason;
import com.company.incert.kms.repository.OutboxEventRepository;
import com.company.incert.kms.service.OutboxRelayService;
import com.company.incert.kms.service.RevocationJob;
import com.company.incert.kms.service.RevocationService;
import com.company.incert.kms.service.RevocationService.CertificateNotFoundException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Dev-only REST endpoints for manual KMS operations, certificate status updates,
 * and outbox reconciliation.
 */
@Slf4j
@RestController
@RequestMapping("/kms")
@Profile("dev")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
@Tag(name = "KMS Certificate Management", description = "Endpoints for managing PKI certificate lifecycles, revocations, and outbox event triggers")
public class KmsAdminController {

    private final RevocationService revocationService;
    private final OutboxRelayService outboxRelay;
    private final RevocationJob revocationJob;
    private final OutboxEventRepository outboxRepository;

    @Operation(summary = "List all certificates", description = "Retrieves the complete inventory of managed certificates and their current statuses")
    @ApiResponse(responseCode = "200", description = "List of certificates retrieved successfully")
    @GetMapping("/certificates")
    public List<Certificate> listCertificates() {
        return revocationService.listAll();
    }

    /** Full status snapshot, usable by an OCSP reconciliation job. */
    @Operation(summary = "Get certificate inventory snapshot", description = "Full status snapshot used for OCSP reconciliation and audit checks")
    @ApiResponse(responseCode = "200", description = "Snapshot retrieved successfully")
    @GetMapping("/snapshot")
    public List<Certificate> snapshot() {
        return revocationService.listAll();
    }

    /**
     * Accepts serials in any hex form (e.g. openssl "-serial" output, with or without
     * a leading sign byte) and converts to the canonical DER-content-bytes hex encoding.
     */
    static String normalizeSerial(String serial) {
        String s = serial.toLowerCase().replace(":", "");
        if (s.startsWith("0x")) s = s.substring(2);
        return HexFormat.of().formatHex(new java.math.BigInteger(s, 16).toByteArray());
    }

    @Operation(summary = "Revoke certificate", description = "Revokes a certificate by serial number and publishes a status change event via the transactional outbox")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Certificate revoked successfully",
                content = @Content(schema = @Schema(implementation = Certificate.class))),
        @ApiResponse(responseCode = "400", description = "Invalid revocation reason"),
        @ApiResponse(responseCode = "404", description = "Certificate not found")
    })
    @PostMapping("/certificates/{serial}/revoke")
    public ResponseEntity<?> revoke(
            @Parameter(description = "Certificate serial number in hexadecimal format", example = "008a5232e619344f2ebdb9b35f93e6a70d")
            @PathVariable("serial") String serial,
            @Parameter(description = "Standard RFC 5280 revocation reason", example = "KEY_COMPROMISE")
            @RequestParam(value = "reason", defaultValue = "KEY_COMPROMISE") String reasonStr) {
        try {
            RevocationReason reason = RevocationReason.valueOf(
                    reasonStr.toUpperCase().replace("-", "_"));
            Certificate cert = revocationService.revoke(normalizeSerial(serial), reason);
            outboxRelay.relay();
            return ResponseEntity.ok(cert);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Invalid revocation reason: " + reasonStr,
                    "validReasons", RevocationReason.values()));
        } catch (CertificateNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Unrevoke certificate", description = "Reinstates a previously held certificate (CERTIFICATE_HOLD) back to GOOD status")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Certificate reinstated successfully",
                content = @Content(schema = @Schema(implementation = Certificate.class))),
        @ApiResponse(responseCode = "400", description = "Certificate cannot be unrevoked (not on CERTIFICATE_HOLD)"),
        @ApiResponse(responseCode = "404", description = "Certificate not found")
    })
    @PostMapping("/certificates/{serial}/unrevoke")
    public ResponseEntity<?> unrevoke(
            @Parameter(description = "Certificate serial number in hexadecimal format")
            @PathVariable("serial") String serial) {
        try {
            Certificate cert = revocationService.unrevoke(normalizeSerial(serial));
            outboxRelay.relay();
            return ResponseEntity.ok(cert);
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (CertificateNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Update certificate status", description = "Explicitly set certificate status to GOOD, REVOKED, or CERTIFICATE_HOLD with custom reason and timestamp")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Certificate status updated successfully",
                content = @Content(schema = @Schema(implementation = Certificate.class))),
        @ApiResponse(responseCode = "400", description = "Invalid status or parameters"),
        @ApiResponse(responseCode = "404", description = "Certificate not found")
    })
    @PostMapping("/certificates/{serial}/status")
    public ResponseEntity<?> updateStatus(
            @Parameter(description = "Certificate serial number in hexadecimal format")
            @PathVariable("serial") String serial,
            @RequestBody StatusUpdateRequest request) {
        try {
            CertificateStatus targetStatus = CertificateStatus.valueOf(request.getStatus().toUpperCase());
            RevocationReason reason = null;
            if (request.getReason() != null && !request.getReason().isBlank()) {
                reason = RevocationReason.valueOf(request.getReason().toUpperCase().replace("-", "_"));
            }

            Instant revTime = request.getRevocationTime() != null ? request.getRevocationTime() : Instant.now();
            Certificate cert = revocationService.updateStatus(normalizeSerial(serial), targetStatus, reason, revTime);
            outboxRelay.relay();
            return ResponseEntity.ok(cert);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid status or reason: " + e.getMessage()));
        } catch (CertificateNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Get outbox sync status", description = "Returns total count of managed certificates and pending unsent events in the outbox table")
    @ApiResponse(responseCode = "200", description = "Sync status retrieved successfully")
    @GetMapping("/audit/sync-status")
    public ResponseEntity<Map<String, Object>> getSyncStatus() {
        long totalCerts = revocationService.listAll().size();
        long pendingOutbox = outboxRepository.countBySentFalse();
        return ResponseEntity.ok(Map.of(
                "totalCertificates", totalCerts,
                "pendingOutboxEvents", pendingOutbox,
                "synchronized", pendingOutbox == 0,
                "timestamp", Instant.now()
        ));
    }

    @Operation(summary = "Sync all certificates to responder", description = "Re-publishes status events for all managed certificates to guarantee receiver inbox parity")
    @ApiResponse(responseCode = "200", description = "Re-queue triggered successfully")
    @PostMapping("/audit/sync-all")
    public ResponseEntity<Map<String, Object>> syncAll() {
        int queued = revocationService.syncAll();
        outboxRelay.relay();
        return ResponseEntity.ok(Map.of(
                "message", "Successfully queued and relayed all certificates to outbox",
                "count", queued,
                "timestamp", Instant.now()
        ));
    }

    @Operation(summary = "Trigger random revocation", description = "Manually triggers the background revocation simulation job once")
    @ApiResponse(responseCode = "200", description = "Simulation job triggered")
    @PostMapping("/certificates/trigger-revocation")
    public ResponseEntity<Map<String, String>> triggerRevocation() {
        revocationJob.runNow();
        outboxRelay.relay();
        return ResponseEntity.ok(Map.of("status", "Revocation job triggered"));
    }

    @Operation(summary = "Run background revocation job", description = "Alias to trigger the background revocation simulation job once")
    @ApiResponse(responseCode = "200", description = "Simulation job triggered")
    @PostMapping("/jobs/revocation/run")
    public ResponseEntity<Map<String, String>> runJob() {
        revocationJob.runNow();
        outboxRelay.relay();
        return ResponseEntity.ok(Map.of("status", "Revocation job executed"));
    }

    @Data
    public static class StatusUpdateRequest {
        private String status; // GOOD, REVOKED, CERTIFICATE_HOLD
        private String reason; // e.g. KEY_COMPROMISE
        private Instant revocationTime;
    }
}

