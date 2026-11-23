package com.company.incert.ocsp.auth.controller;

import com.company.incert.ocsp.shared.config.OpenApiConfig;
import com.company.incert.ocsp.auth.dto.CreateUserRequest;
import com.company.incert.ocsp.auth.dto.RoleDto;
import com.company.incert.ocsp.auth.dto.UpdateUserRequest;
import com.company.incert.ocsp.auth.dto.UserCertificateDto;
import com.company.incert.ocsp.auth.dto.UserDto;
import com.company.incert.ocsp.auth.service.IdentityService;
import com.company.incert.ocsp.auth.service.UserCertificateService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Admin-only REST controller for managing users and RBAC role assignments.
 * Delegates to the active {@link IdentityService} strategy ({@code LocalIdentityService}
 * or {@code KeycloakIdentityService}) without inspecting {@code app.auth.mode}.
 */
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasPermission(null, 'USER_MANAGE')")
@Tag(name = "User Management", description = "Admin-only user and RBAC role management endpoints")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.BEARER_AUTH_SCHEME)
public class UserManagementController {

    private final IdentityService identityService;
    private final UserCertificateService userCertificateService;

    public record ResetPasswordPayload(String newPassword) {}
    public record SetEnabledPayload(boolean enabled) {}
    public record AssignCertificatePayload(String certificatePem) {}

    @Operation(summary = "List all active users", description = "Returns all non-deleted users and their assigned roles (ADMIN only)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Users listed successfully"),
        @ApiResponse(responseCode = "403", description = "Forbidden — requires ROLE_ADMIN")
    })
    @GetMapping("/users")
    public ResponseEntity<List<UserDto>> listUsers() {
        return ResponseEntity.ok(identityService.listUsers());
    }

    @Operation(summary = "List all available RBAC roles", description = "Returns all roles defined in the system (ADMIN only)")
    @GetMapping("/roles")
    public ResponseEntity<List<RoleDto>> listRoles() {
        return ResponseEntity.ok(identityService.listRoles());
    }

    @Operation(summary = "Create a new user", description = "Delegates to the active IdentityService strategy (ADMIN only)")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "User created successfully"),
        @ApiResponse(responseCode = "400", description = "Duplicate username, invalid role, or mode mismatch"),
        @ApiResponse(responseCode = "403", description = "Forbidden — requires ROLE_ADMIN")
    })
    @PostMapping("/users")
    public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserRequest request) {
        try {
            return ResponseEntity.status(HttpStatus.CREATED).body(identityService.createUser(request));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Update user profile, roles, or status", description = "Updates an existing user via IdentityService (ADMIN only)")
    @PutMapping("/users/{id}")
    public ResponseEntity<?> updateUser(
            @PathVariable String id,
            @Valid @RequestBody UpdateUserRequest request,
            Authentication auth) {
        try {
            String actingUsername = auth != null ? auth.getName() : "";
            return ResponseEntity.ok(identityService.updateUser(id, request, actingUsername));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Enable or disable a user", description = "Sets enabled state via IdentityService (ADMIN only)")
    @PutMapping("/users/{id}/enabled")
    public ResponseEntity<?> setEnabled(
            @PathVariable String id,
            @RequestBody SetEnabledPayload payload,
            Authentication auth) {
        try {
            String actingUsername = auth != null ? auth.getName() : "";
            return ResponseEntity.ok(identityService.setEnabled(id, payload.enabled(), actingUsername));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Reset password or trigger Keycloak reset email", description = "Resets password in LOCAL mode or sends UPDATE_PASSWORD email in KEYCLOAK mode (ADMIN only)")
    @PostMapping("/users/{id}/reset-password")
    public ResponseEntity<?> resetPassword(
            @PathVariable String id,
            @RequestBody(required = false) ResetPasswordPayload payload) {
        try {
            identityService.resetPassword(id, payload != null ? payload.newPassword() : null);
            return ResponseEntity.ok(Map.of("status", "PASSWORD_RESET_INITIATED"));
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "List certificates assigned to a user", description = "Lists X.509 client certificates assigned to the user for optional mTLS (ADMIN only)")
    @GetMapping("/users/{id}/certificates")
    public ResponseEntity<?> listUserCertificates(@PathVariable String id) {
        try {
            List<UserCertificateDto> certs = userCertificateService.listUserCertificates(id);
            return ResponseEntity.ok(certs);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Assign an X.509 certificate to a user", description = "Parses PEM certificate, stores SHA-256 fingerprint and metadata in user_certificates (ADMIN only)")
    @PostMapping("/users/{id}/certificates")
    public ResponseEntity<?> assignUserCertificate(
            @PathVariable String id,
            @RequestBody AssignCertificatePayload payload) {
        try {
            UserCertificateDto created = userCertificateService.assignCertificate(
                    id, payload != null ? payload.certificatePem() : null);
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Remove a user certificate assignment", description = "Unassigns an X.509 client certificate from the user (ADMIN only)")
    @DeleteMapping("/users/{id}/certificates/{certId}")
    public ResponseEntity<?> removeUserCertificate(
            @PathVariable String id,
            @PathVariable String certId) {
        try {
            userCertificateService.removeCertificate(id, certId);
            return ResponseEntity.ok(Map.of("status", "REMOVED", "certId", certId));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @Operation(summary = "Soft-delete or GDPR-anonymize a user", description = "Soft-deletes a user (and optionally anonymizes PII when anonymizeGdpr=true) (ADMIN only)")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(
            @PathVariable String id,
            @RequestParam(value = "anonymizeGdpr", defaultValue = "false") boolean anonymizeGdpr,
            Authentication auth) {
        try {
            String actingUsername = auth != null ? auth.getName() : "";
            identityService.deleteUser(id, anonymizeGdpr, actingUsername);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
