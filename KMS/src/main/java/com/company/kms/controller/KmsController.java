package com.company.kms.controller;

import com.company.kms.config.KmsKeyMaterial;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.StringWriter;
import java.security.Signature;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * REST controller implementing the three endpoints required by the OCSP subsystem.
 *
 * <p><b>Endpoints:</b>
 * <ul>
 *   <li>{@code POST /api/v1/kms/sign} — sign TBS bytes with the in-memory RSA key</li>
 *   <li>{@code GET  /api/v1/kms/reconciliation} — return the authoritative revoked count</li>
 *   <li>{@code GET  /api/v1/kms/ocsp/signing-cert/active} — return the signing cert chain</li>
 * </ul>
 *
 * <p>This is intentionally simple — no authentication, no HSM. For development only.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class KmsController {

    private final KmsKeyMaterial keyMaterial;

    /** Simulates the number of revoked certs — increment this in integration tests. */
    private final AtomicLong revokedCount = new AtomicLong(0);

    // =========================================================================
    // POST /api/v1/kms/sign
    // =========================================================================

    public record SignRequest(String keyReference, String tbsBytes, String algorithm) {}
    public record SignResponse(String signature) {}

    @PostMapping(
        value = "/api/v1/kms/sign",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<SignResponse> sign(@RequestBody SignRequest request) throws Exception {
        log.debug("KMS sign request: keyRef={} algorithm={} tbsLen={}",
                request.keyReference(), request.algorithm(),
                request.tbsBytes() != null ? request.tbsBytes().length() : 0);

        byte[] tbs = Base64.getDecoder().decode(request.tbsBytes());

        // Use the in-memory RSA private key to produce the signature
        String javaAlgorithm = mapAlgorithm(request.algorithm());
        Signature sig = Signature.getInstance(javaAlgorithm, "BC");
        sig.initSign(keyMaterial.getSigningKeyPair().getPrivate());
        sig.update(tbs);
        byte[] signature = sig.sign();

        String sigBase64 = Base64.getEncoder().encodeToString(signature);
        log.debug("KMS signed {} bytes → {} signature bytes", tbs.length, signature.length);
        return ResponseEntity.ok(new SignResponse(sigBase64));
    }

    // =========================================================================
    // GET /api/v1/kms/reconciliation
    // =========================================================================

    public record ReconciliationResponse(long revokedCount) {}

    @GetMapping(value = "/api/v1/kms/reconciliation",
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ReconciliationResponse> reconcile() {
        long count = revokedCount.get();
        log.debug("KMS reconciliation requested: revokedCount={}", count);
        return ResponseEntity.ok(new ReconciliationResponse(count));
    }

    // =========================================================================
    // GET /api/v1/kms/ocsp/signing-cert/active
    // =========================================================================

    public record SigningCertResponse(
        String keyReference,
        String algorithm,
        List<String> pemChain,
        String notBefore,
        String notAfter
    ) {}

    @GetMapping(value = "/api/v1/kms/ocsp/signing-cert/active",
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SigningCertResponse> getActiveSigningCert() throws Exception {
        String pem = toPem(keyMaterial.getSigningCertificate());

        Instant notBefore = keyMaterial.getSigningCertificate().getNotBefore().toInstant();
        Instant notAfter  = keyMaterial.getSigningCertificate().getNotAfter().toInstant();

        SigningCertResponse response = new SigningCertResponse(
            "mock-ocsp-signing-key-01",
            "SHA256withRSA",
            List.of(pem),
            DateTimeFormatter.ISO_INSTANT.format(notBefore),
            DateTimeFormatter.ISO_INSTANT.format(notAfter)
        );

        log.debug("KMS signing cert requested. notAfter={}", response.notAfter());
        return ResponseEntity.ok(response);
    }

    // =========================================================================
    // POST /api/v1/kms/ocsp/signing-cert/renew
    // Rotates the OCSP signing certificate — regenerates key pair + cert in-memory.
    // In production this would call the HSM/CA to issue a new delegated cert.
    // =========================================================================

    public record RenewRequest(String reason) {}
    public record RenewResponse(
        String requestId,
        String status,
        String keyReference,
        String notBefore,
        String notAfter,
        List<String> pemChain
    ) {}

    @PostMapping(
        value = "/api/v1/kms/ocsp/signing-cert/renew",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<RenewResponse> renewSigningCert(
            @RequestBody(required = false) RenewRequest request) throws Exception {

        String reason = request != null && request.reason() != null ? request.reason() : "unspecified";
        log.info("KMS signing-cert renewal requested. reason={}", reason);

        // Rotate: regenerate key material
        keyMaterial.rotate();

        String pem      = toPem(keyMaterial.getSigningCertificate());
        Instant notBefore = keyMaterial.getSigningCertificate().getNotBefore().toInstant();
        Instant notAfter  = keyMaterial.getSigningCertificate().getNotAfter().toInstant();
        String requestId  = UUID.randomUUID().toString();

        log.info("KMS signing-cert renewed. requestId={} notAfter={}", requestId, notAfter);

        return ResponseEntity.ok(new RenewResponse(
            requestId,
            "ISSUED",
            "mock-ocsp-signing-key-" + System.currentTimeMillis(),
            DateTimeFormatter.ISO_INSTANT.format(notBefore),
            DateTimeFormatter.ISO_INSTANT.format(notAfter),
            List.of(pem)
        ));
    }

    // =========================================================================
    // Test helper: POST /api/v1/kms/test/increment-revoked
    // Increments the simulated revoked count — useful in integration tests.
    // =========================================================================

    @PostMapping("/api/v1/kms/test/increment-revoked")
    public ResponseEntity<Map<String, Long>> incrementRevoked() {
        long newCount = revokedCount.incrementAndGet();
        return ResponseEntity.ok(Map.of("revokedCount", newCount));
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    private String mapAlgorithm(String kmsAlgorithm) {
        return switch (kmsAlgorithm) {
            case "SHA256withRSA"   -> "SHA256withRSA";
            case "SHA384withRSA"   -> "SHA384withRSA";
            case "SHA512withRSA"   -> "SHA512withRSA";
            case "SHA256withECDSA" -> "SHA256withECDSA";
            case "SHA384withECDSA" -> "SHA384withECDSA";
            default -> throw new IllegalArgumentException(
                    "Unsupported KMS algorithm: " + kmsAlgorithm);
        };
    }

    private String toPem(java.security.cert.Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(cert);
        }
        return sw.toString();
    }
}
