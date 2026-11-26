package lu.incert.ocsp.signing.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lu.incert.ocsp.shared.config.OpenApiConfig;
import lu.incert.ocsp.signing.dto.SignerCertImportRequest;
import lu.incert.ocsp.signing.dto.SignerCsrRequest;
import lu.incert.ocsp.signing.dto.SignerDto;
import lu.incert.ocsp.signing.dto.SignerRequest;
import lu.incert.ocsp.signing.service.OcspSignerManagementService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST endpoints for first-class OCSP {@code Signer} aggregates (ordered HSM Vslots, provider,
 * key generation, PKCS#10 CSR generation/retrieval, and X.509 certificate import/retrieval).
 * <p>
 * Mounted under both {@code /api/v1/admin/signers} and {@code /api/v1/admin/signer}.
 */
@RestController
@RequestMapping({"/api/v1/admin/signers", "/api/v1/admin/signer"})
@RequiredArgsConstructor
@Tag(name = "OCSP Signers (HSM Vslots + Key + CSR + Cert)",
     description = "First-class OCSP Signer aggregate managing ordered HSM Vslots, keygen/CSR, and certificate import")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
public class OcspSignerController {

    private final OcspSignerManagementService signerService;

    @Operation(summary = "List all OCSP Signers with their bound HSM Vslots, key info, CSR, and certificate")
    @GetMapping
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_READ')")
    public ResponseEntity<List<SignerDto>> listAll() {
        return ResponseEntity.ok(signerService.listAll());
    }

    @Operation(summary = "Get a single OCSP Signer by ID")
    @GetMapping("/{id}")
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_READ')")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(signerService.getById(id));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Create a new OCSP Signer with 1..N ordered HSM Vslots, key policy, and signing algorithm")
    @PostMapping
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_CREATE_CSR')")
    public ResponseEntity<?> createSigner(@Valid @RequestBody SignerRequest request) {
        try {
            return ResponseEntity.status(HttpStatus.CREATED).body(signerService.createSigner(request));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Update an existing OCSP Signer and its bound HSM Vslots")
    @PutMapping("/{id}")
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_CREATE_CSR')")
    public ResponseEntity<?> updateSigner(@PathVariable Long id, @Valid @RequestBody SignerRequest request) {
        try {
            return ResponseEntity.ok(signerService.updateSigner(id, request));
        } catch (IllegalArgumentException e) {
            HttpStatus status = e.getMessage() != null && e.getMessage().startsWith("Signer not found")
                    ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Delete an inactive OCSP Signer")
    @DeleteMapping("/{id}")
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_DELETE')")
    public ResponseEntity<?> deleteSigner(@PathVariable Long id) {
        try {
            signerService.deleteSigner(id);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Generate keypair in the Signer's HSM Vslot and create a signed PKCS#10 CSR (POST /signer/{id}/csr)")
    @PostMapping("/{id}/csr")
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_CREATE_CSR')")
    public ResponseEntity<?> generateCsr(
            @PathVariable Long id,
            @RequestBody(required = false) SignerCsrRequest request) {
        try {
            return ResponseEntity.status(HttpStatus.CREATED).body(signerService.generateCsr(id, request));
        } catch (IllegalArgumentException e) {
            HttpStatus status = e.getMessage() != null && e.getMessage().startsWith("Signer not found")
                    ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException | UnsupportedOperationException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Get the Signer's PKCS#10 CSR if generated (GET /signer/{id}/csr, optional ?generateIfMissing=true)")
    @GetMapping("/{id}/csr")
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_READ')")
    public ResponseEntity<?> getCsr(
            @PathVariable Long id,
            @RequestParam(name = "generateIfMissing", defaultValue = "false") boolean generateIfMissing) {
        try {
            return signerService.getCsr(id, generateIfMissing)
                    .<ResponseEntity<?>>map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("error", "No CSR generated yet for signer " + id
                                    + " (call POST /api/v1/admin/signers/" + id + "/csr first)")));
        } catch (IllegalArgumentException e) {
            HttpStatus status = e.getMessage() != null && e.getMessage().startsWith("Signer not found")
                    ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Get the Signer's X.509 certificate if imported (GET /signer/{id}/cert)")
    @GetMapping("/{id}/cert")
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_READ')")
    public ResponseEntity<?> getCertificate(@PathVariable Long id) {
        try {
            return signerService.getCertificate(id)
                    .<ResponseEntity<?>>map(ResponseEntity::ok)
                    .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                            .body(Map.of("error", "No certificate imported yet for signer " + id)));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Import a CA-signed X.509 certificate into the Signer and its HSM Vslot(s) (POST /signer/{id}/cert)")
    @PostMapping("/{id}/cert")
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_IMPORT')")
    public ResponseEntity<?> importCertificate(
            @PathVariable Long id,
            @Valid @RequestBody SignerCertImportRequest request,
            Authentication auth) {
        boolean activateRequested = request.activateImmediately() == null || Boolean.TRUE.equals(request.activateImmediately());
        if (activateRequested && !isAdmin(auth)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Only ROLE_ADMIN can activate a signer immediately on certificate import"));
        }
        try {
            return ResponseEntity.ok(signerService.importCertificate(id, request));
        } catch (IllegalArgumentException e) {
            HttpStatus status = e.getMessage() != null && e.getMessage().startsWith("Signer not found")
                    ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Activate an OCSP Signer for live RFC 6960 signing")
    @PutMapping("/{id}/activate")
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_ACTIVATE')")
    public ResponseEntity<?> activateSigner(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(signerService.activateSigner(id));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Deactivate an active OCSP Signer")
    @PutMapping("/{id}/deactivate")
    @PreAuthorize("hasPermission(null, 'SIGNING_CERT_DEACTIVATE')")
    public ResponseEntity<?> deactivateSigner(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(signerService.deactivateSigner(id));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    private static boolean isAdmin(Authentication auth) {
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }
}
