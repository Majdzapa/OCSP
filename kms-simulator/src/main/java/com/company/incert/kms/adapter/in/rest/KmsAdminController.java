package com.company.incert.kms.adapter.in.rest;

import com.company.incert.kms.adapter.in.job.RevocationJobAdapter;
import com.company.incert.kms.adapter.out.jpa.SpringDataOutboxRepository;
import com.company.incert.kms.adapter.out.rabbit.RabbitMqOutboxRelayAdapter;
import com.company.incert.kms.application.port.in.ListCertificatesUseCase;
import com.company.incert.kms.application.port.in.RevokeCertificateUseCase;
import com.company.incert.kms.application.port.in.SyncAllCertificatesUseCase;
import com.company.incert.kms.application.port.in.UnrevokeCertificateUseCase;
import com.company.incert.kms.application.port.in.UpdateCertificateStatusUseCase;
import com.company.incert.kms.application.service.RevocationService.CertificateNotFoundException;
import com.company.incert.kms.domain.Certificate;
import com.company.incert.kms.domain.CertificateStatus;
import com.company.incert.kms.domain.RevocationReason;
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
import java.util.List;
import java.util.Map;

/**
 * Dev-only REST endpoints for manual KMS operations, certificate status updates,
 * and outbox reconciliation.
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
    private final UpdateCertificateStatusUseCase updateStatusUseCase;
    private final SyncAllCertificatesUseCase syncAllUseCase;
    private final RevocationJobAdapter revocationJob;
    private final SpringDataOutboxRepository outboxRepository;
    private final RabbitMqOutboxRelayAdapter outboxRelay;

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
            outboxRelay.relay();
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
            outboxRelay.relay();
            return ResponseEntity.ok(cert);
        } catch (CertificateNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @Data
    public static class UpdateStatusRequest {
        @Schema(description = "Target status: GOOD or REVOKED", example = "REVOKED", requiredMode = Schema.RequiredMode.REQUIRED)
        private String status;

        @Schema(description = "RFC 5280 revocation reason", example = "KEY_COMPROMISE")
        private String reason;

        @Schema(description = "Optional custom revocation time in ISO-8601 format")
        private Instant revocationTime;
    }

    @Operation(summary = "Update certificate status", description = "Directly updates a certificate status (GOOD, REVOKED, or CERTIFICATE_HOLD) with custom reason and timestamp, publishing via outbox")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Status updated successfully",
                content = @Content(schema = @Schema(implementation = Certificate.class))),
        @ApiResponse(responseCode = "400", description = "Invalid status or reason parameter"),
        @ApiResponse(responseCode = "404", description = "Certificate not found")
    })
    @PostMapping("/certificates/{serial}/status")
    public ResponseEntity<?> updateCertificateStatus(
            @Parameter(description = "Certificate serial number in hex format", example = "008a5232e619344f2ebdb9b35f93e6a70d")
            @PathVariable("serial") String serial,
            @RequestBody UpdateStatusRequest request) {
        try {
            String normSerial = normalizeSerial(serial);
            String stStr = request.getStatus() != null ? request.getStatus().trim().toUpperCase() : "REVOKED";

            CertificateStatus targetStatus;
            RevocationReason reason = null;

            if ("HOLD".equals(stStr) || "CERTIFICATE_HOLD".equals(stStr)) {
                targetStatus = CertificateStatus.REVOKED;
                reason = RevocationReason.CERTIFICATE_HOLD;
            } else {
                targetStatus = CertificateStatus.valueOf(stStr);
                if (targetStatus == CertificateStatus.REVOKED && request.getReason() != null && !request.getReason().isBlank()) {
                    reason = RevocationReason.valueOf(request.getReason().trim().toUpperCase().replace("-", "_"));
                }
            }

            Certificate updated = updateStatusUseCase.updateStatus(normSerial, targetStatus, reason, request.getRevocationTime());
            outboxRelay.relay();
            return ResponseEntity.ok(updated);
        } catch (CertificateNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid status or reason: " + e.getMessage()));
        }
    }

    @Operation(summary = "Get outbox & sync status", description = "Returns KMS certificate inventory metrics and transactional outbox relay stats")
    @ApiResponse(responseCode = "200", description = "Status returned successfully")
    @GetMapping("/audit/sync-status")
    public ResponseEntity<Map<String, Object>> getSyncStatus() {
        List<Certificate> certs = listUseCase.listAll();
        long totalCerts = certs.size();
        long goodCerts = certs.stream().filter(c -> c.status() == CertificateStatus.GOOD).count();
        long revokedCerts = certs.stream().filter(c -> c.status() == CertificateStatus.REVOKED).count();

        long totalOutbox = outboxRepository.count();
        long pendingOutbox = outboxRepository.findBySentFalseOrderByCreatedAtAsc().size();
        long sentOutbox = totalOutbox - pendingOutbox;

        return ResponseEntity.ok(Map.of(
                "totalCertificates", totalCerts,
                "goodCertificates", goodCerts,
                "revokedCertificates", revokedCerts,
                "totalOutboxEvents", totalOutbox,
                "sentOutboxEvents", sentOutbox,
                "pendingOutboxEvents", pendingOutbox
        ));
    }

    @Operation(summary = "Sync all certificates to RabbitMQ outbox", description = "Re-publishes outbox status change events for 100% of managed certificates to guarantee responder has complete inventory")
    @ApiResponse(responseCode = "200", description = "All certificates queued and relayed to outbox")
    @PostMapping("/audit/sync-all")
    public ResponseEntity<Map<String, Object>> syncAllCertificates() {
        int count = syncAllUseCase.syncAll();
        outboxRelay.relay();
        return ResponseEntity.ok(Map.of(
                "status", "synced",
                "certificatesQueued", count,
                "message", "Outbox events created and relayed to RabbitMQ exchange for all " + count + " certificates"
        ));
    }

    @Operation(summary = "Trigger revocation job immediately", description = "Forces immediate execution of the background revocation simulation job")
    @ApiResponse(responseCode = "200", description = "Revocation job triggered")
    @PostMapping("/jobs/revocation/run")
    public ResponseEntity<?> triggerRevocationJob() {
        revocationJob.runNow();
        outboxRelay.relay();
        return ResponseEntity.ok(Map.of("status", "triggered"));
    }
}
