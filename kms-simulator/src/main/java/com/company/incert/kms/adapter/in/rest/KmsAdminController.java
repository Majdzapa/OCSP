package com.company.incert.kms.adapter.in.rest;

import com.company.incert.kms.adapter.in.job.RevocationJobAdapter;
import com.company.incert.kms.application.port.in.ListCertificatesUseCase;
import com.company.incert.kms.application.port.in.RevokeCertificateUseCase;
import com.company.incert.kms.application.port.in.UnrevokeCertificateUseCase;
import com.company.incert.kms.application.service.RevocationService.CertificateNotFoundException;
import com.company.incert.kms.domain.Certificate;
import com.company.incert.kms.domain.RevocationReason;
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
public class KmsAdminController {

    private final RevokeCertificateUseCase revokeUseCase;
    private final UnrevokeCertificateUseCase unrevokeUseCase;
    private final ListCertificatesUseCase listUseCase;
    private final RevocationJobAdapter revocationJob;

    @GetMapping("/certificates")
    public List<Certificate> listCertificates() {
        return listUseCase.listAll();
    }

    /** Full status snapshot, usable by an OCSP reconciliation job. */
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

    @PostMapping("/certificates/{serial}/revoke")
    public ResponseEntity<?> revoke(
            @PathVariable("serial") String serial,
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

    @PostMapping("/certificates/{serial}/unrevoke")
    public ResponseEntity<?> unrevoke(@PathVariable("serial") String serial) {
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

    @PostMapping("/jobs/revocation/run")
    public ResponseEntity<?> triggerRevocationJob() {
        revocationJob.runNow();
        return ResponseEntity.ok(Map.of("status", "triggered"));
    }
}
