package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.OpenApiConfig;
import com.company.incert.ocsp.dto.AddSigningCertificateRequest;
import com.company.incert.ocsp.dto.GenerateCsrRequest;
import com.company.incert.ocsp.dto.GenerateCsrResponse;
import com.company.incert.ocsp.dto.HsmInfoDto;
import com.company.incert.ocsp.dto.SigningCertValidityReportDto;
import com.company.incert.ocsp.dto.SigningCertificateDto;
import com.company.incert.ocsp.service.SigningCertificateService;
import com.company.incert.ocsp.service.SigningCertificateValidityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin/signing-certificates")
@Tag(name = "Signing Certificates", description = "Management of OCSP response signing certificates and key rotation")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
public class SigningCertificateController {

    private final SigningCertificateService certificateService;
    private final SigningCertificateValidityService validityService;

    public SigningCertificateController(SigningCertificateService certificateService) {
        this(certificateService, null);
    }

    @Autowired
    public SigningCertificateController(
            SigningCertificateService certificateService,
            SigningCertificateValidityService validityService) {
        this.certificateService = certificateService;
        this.validityService = validityService;
    }

    @Operation(summary = "List all signing certificates", description = "Retrieves all registered signing certificates and their active status")
    @GetMapping
    public ResponseEntity<List<SigningCertificateDto>> listAll() {
        return ResponseEntity.ok(certificateService.listAll());
    }

    @Operation(summary = "Get the currently active signing certificate", description = "Returns the single certificate currently used for signing responses")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Active certificate found"),
        @ApiResponse(responseCode = "404", description = "No active signing certificate found")
    })
    @GetMapping("/active")
    public ResponseEntity<SigningCertificateDto> getActive() {
        return certificateService.getActiveCertificate()
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @Operation(summary = "Add a new signing certificate", description = "Registers a new signing certificate from PEM. Optionally activates it immediately.")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Certificate registered successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid certificate PEM or duplicate alias")
    })
    @PostMapping
    public ResponseEntity<?> addCertificate(@Valid @RequestBody AddSigningCertificateRequest request) {
        try {
            SigningCertificateDto created = certificateService.addCertificate(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Activate signing certificate", description = "Marks the specified certificate as active for signing responses for its issuing CA (multiple active signers supported)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Certificate activated successfully"),
        @ApiResponse(responseCode = "400", description = "Certificate is expired, missing HSM key, or not found")
    })
    @PutMapping("/{id}/activate")
    public ResponseEntity<?> activate(
            @Parameter(description = "ID of the signing certificate to activate")
            @PathVariable Long id) {
        try {
            SigningCertificateDto activated = certificateService.activate(id);
            return ResponseEntity.ok(activated);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Deactivate signing certificate", description = "Deactivates an active signing certificate (at least one active certificate must remain)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Certificate deactivated successfully"),
        @ApiResponse(responseCode = "400", description = "Cannot deactivate the last remaining active certificate or not found")
    })
    @PutMapping("/{id}/deactivate")
    public ResponseEntity<?> deactivate(
            @Parameter(description = "ID of the signing certificate to deactivate")
            @PathVariable Long id) {
        try {
            SigningCertificateDto deactivated = certificateService.deactivate(id);
            return ResponseEntity.ok(deactivated);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Get HSM PKCS#11 configuration and token key labels", description = "Returns configured PKCS#11 library path, token label, slot index, and existing key labels")
    @GetMapping("/hsm-info")
    public ResponseEntity<HsmInfoDto> getHsmInfo() {
        return ResponseEntity.ok(certificateService.getHsmInfo());
    }

    @Operation(summary = "Generate a PKCS#10 CSR from the HSM", description = "Generates (or reuses) a non-extractable keypair in the HSM and returns a PEM-encoded PKCS#10 CSR")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "CSR generated successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid request or HSM key conflict")
    })
    @PostMapping("/csr")
    public ResponseEntity<?> generateCsr(@Valid @RequestBody GenerateCsrRequest request) {
        try {
            GenerateCsrResponse csr = certificateService.generateCsr(request);
            return ResponseEntity.ok(csr);
        } catch (IllegalArgumentException | IllegalStateException | UnsupportedOperationException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Delete an inactive signing certificate", description = "Removes a certificate from the registry. Cannot delete the active certificate.")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Certificate deleted"),
        @ApiResponse(responseCode = "400", description = "Cannot delete active certificate"),
        @ApiResponse(responseCode = "404", description = "Certificate not found")
    })
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(
            @Parameter(description = "ID of the signing certificate to delete")
            @PathVariable Long id) {
        try {
            certificateService.delete(id);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Get signing certificates validity report and 3-day expiry alerts",
               description = "Returns the current validity report for all signing certificates, including active alerts for certificates expiring within 3 days or already expired")
    @GetMapping("/validity")
    public ResponseEntity<SigningCertValidityReportDto> getValidityReport() {
        return ResponseEntity.ok(validityService.getValidityReport());
    }

    @Operation(summary = "Run the daily signing certificate validity check now",
               description = "Triggers the daily validity check job immediately, logs alerts for certificates expiring within 3 days, and returns the updated report")
    @PostMapping("/validity/check")
    public ResponseEntity<SigningCertValidityReportDto> runValidityCheckNow() {
        return ResponseEntity.ok(validityService.runDailyValidityCheck());
    }

    public record RenewalCsrRequest(Boolean reuseExistingKey, String newKeyLabel, Integer keySize) {}

    @Operation(summary = "Create a renewal CSR for an existing signing certificate",
               description = "Generates a PKCS#10 renewal CSR for the specified signing certificate (reusing its HSM key by default or generating a new key)")
    @PostMapping("/{id}/renew-request")
    public ResponseEntity<?> createRenewalRequest(
            @PathVariable Long id,
            @RequestBody(required = false) RenewalCsrRequest request) {
        try {
            Boolean reuse = request != null ? request.reuseExistingKey() : Boolean.TRUE;
            String newLabel = request != null ? request.newKeyLabel() : null;
            Integer keySize = request != null ? request.keySize() : null;
            GenerateCsrResponse csr = validityService.createRenewalRequest(id, reuse, newLabel, keySize);
            return ResponseEntity.ok(csr);
        } catch (IllegalArgumentException | IllegalStateException | UnsupportedOperationException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}

