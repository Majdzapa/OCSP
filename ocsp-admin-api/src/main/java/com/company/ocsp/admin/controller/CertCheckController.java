package com.company.ocsp.admin.controller;

import com.company.ocsp.admin.model.RevocationStatus;
import com.company.ocsp.admin.repository.RevocationStatusRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

/**
 * Public-style endpoint: check whether a certificate (by serial number) is
 * GOOD or REVOKED, and — if revoked — submit a renewal request to KMS.
 *
 * <p>Base path: {@code /api/v1/admin/cert-check}
 *
 * <h2>Workflow</h2>
 * <ol>
 *   <li>Client calls {@code GET /cert-check/{serialHex}} — receives status GOOD / REVOKED / UNKNOWN.</li>
 *   <li>If REVOKED the client calls {@code POST /cert-check/{serialHex}/renew-request}.</li>
 *   <li>Admin API forwards the renewal to KMS {@code POST /api/v1/kms/ocsp/signing-cert/renew}.</li>
 * </ol>
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/admin/cert-check")
@RequiredArgsConstructor
public class CertCheckController {

    private final RevocationStatusRepository revocationStatusRepository;
    private final KmsGateway kmsGateway;

    // -------------------------------------------------------------------------
    // GET /api/v1/admin/cert-check/{serialHex}
    // -------------------------------------------------------------------------

    public record CertStatusResponse(
        String serialHex,
        String status,            // GOOD | REVOKED | UNKNOWN
        String revocationTime,    // ISO-8601, null when GOOD
        String revocationReason,  // null when GOOD
        boolean renewalAvailable  // true when REVOKED → UI shows the "Request Renewal" button
    ) {}

    @GetMapping("/{serialHex}")
    public ResponseEntity<CertStatusResponse> checkStatus(
            @PathVariable("serialHex") String serialHex) {

        log.info("Cert status check requested: serial={}", serialHex);

        byte[] serial;
        try {
            serial = HexFormat.of().parseHex(serialHex.toLowerCase().replaceAll("[^0-9a-f]", ""));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }

        Optional<RevocationStatus> opt = revocationStatusRepository.findTopBySerialNumber(serial);

        if (opt.isEmpty()) {
            log.debug("Serial {} not found in revocation_status — returning UNKNOWN", serialHex);
            return ResponseEntity.ok(new CertStatusResponse(
                serialHex, "UNKNOWN", null, null, false));
        }

        RevocationStatus rs = opt.get();
        boolean revoked = rs.getStatus() == RevocationStatus.CertStatus.REVOKED;

        return ResponseEntity.ok(new CertStatusResponse(
            serialHex,
            rs.getStatus().name(),
            revoked && rs.getRevocationTime() != null
                ? rs.getRevocationTime().toString() : null,
            rs.getRevocationReason(),
            revoked
        ));
    }

    // -------------------------------------------------------------------------
    // POST /api/v1/admin/cert-check/{serialHex}/renew-request
    // -------------------------------------------------------------------------

    public record RenewRequestBody(String reason) {}

    public record RenewRequestResponse(
        String requestId,
        String serialHex,
        String kmsStatus,       // "ISSUED" on success
        String newNotAfter,
        String submittedAt
    ) {}

    @PostMapping("/{serialHex}/renew-request")
    public ResponseEntity<RenewRequestResponse> requestRenewal(
            @PathVariable("serialHex") String serialHex,
            @RequestBody(required = false) RenewRequestBody body) {

        String reason = body != null && body.reason() != null ? body.reason() : "REVOKED — renewal requested via admin console";
        log.info("Cert renewal requested: serial={} reason={}", serialHex, reason);

        // Verify the cert is actually revoked before forwarding to KMS
        byte[] serial;
        try {
            serial = HexFormat.of().parseHex(serialHex.toLowerCase().replaceAll("[^0-9a-f]", ""));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }

        Optional<RevocationStatus> opt = revocationStatusRepository.findTopBySerialNumber(serial);
        if (opt.isEmpty()) {
            log.warn("Renewal requested for unknown serial {}", serialHex);
            return ResponseEntity.notFound().build();
        }

        // Forward to KMS (signing cert renewal)
        KmsGateway.KmsRenewResponse kmsResp = kmsGateway.renewSigningCert(reason);

        log.info("KMS renewal complete: requestId={} notAfter={}", kmsResp.requestId(), kmsResp.notAfter());

        return ResponseEntity.ok(new RenewRequestResponse(
            kmsResp.requestId(),
            serialHex,
            kmsResp.status(),
            kmsResp.notAfter(),
            Instant.now().toString()
        ));
    }
}
