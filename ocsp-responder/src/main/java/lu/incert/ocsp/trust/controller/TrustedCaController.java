package lu.incert.ocsp.trust.controller;

import lu.incert.ocsp.shared.config.OpenApiConfig;
import lu.incert.ocsp.trust.dto.TrustedCaDto;
import lu.incert.ocsp.trust.service.TrustedCaService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST endpoints for managing Trusted CA certificates used to verify mTLS client certificates.
 * Changes hot-reload immediately into memory without requiring an application restart.
 */
@RestController
@RequestMapping("/api/v1/admin/trusted-cas")
@RequiredArgsConstructor
@Tag(name = "Trusted CAs (mTLS)", description = "Hot-reloaded Trusted CA management for mTLS user certificate verification")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
public class TrustedCaController {

    private final TrustedCaService trustedCaService;

    public record ImportTrustedCaRequest(String alias, String certificatePem) {}
    public record ToggleTrustedCaRequest(boolean enabled) {}

    @Operation(summary = "List all Trusted CAs")
    @GetMapping
    @PreAuthorize("hasPermission(null, 'TRUSTED_CA_READ')")
    public ResponseEntity<List<TrustedCaDto>> listTrustedCas() {
        return ResponseEntity.ok(trustedCaService.listTrustedCas());
    }

    @Operation(summary = "Import a Trusted CA certificate (hot-reloaded immediately without restart)")
    @PostMapping
    @PreAuthorize("hasPermission(null, 'TRUSTED_CA_MANAGE')")
    public ResponseEntity<?> importTrustedCa(@RequestBody ImportTrustedCaRequest request) {
        try {
            TrustedCaDto created = trustedCaService.importTrustedCa(
                    request != null ? request.alias() : null,
                    request != null ? request.certificatePem() : null);
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Enable or disable a Trusted CA (hot-reloaded immediately)")
    @PutMapping("/{id}/enabled")
    @PreAuthorize("hasPermission(null, 'TRUSTED_CA_MANAGE')")
    public ResponseEntity<?> setEnabled(@PathVariable String id, @RequestBody ToggleTrustedCaRequest request) {
        try {
            return ResponseEntity.ok(trustedCaService.setEnabled(id, request != null && request.enabled()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Delete a Trusted CA (hot-reloaded immediately)")
    @DeleteMapping("/{id}")
    @PreAuthorize("hasPermission(null, 'TRUSTED_CA_MANAGE')")
    public ResponseEntity<?> deleteTrustedCa(@PathVariable String id) {
        try {
            trustedCaService.deleteTrustedCa(id);
            return ResponseEntity.ok(Map.of("status", "DELETED", "id", id));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}

