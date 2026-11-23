package com.company.incert.ocsp.auth.controller;

import com.company.incert.ocsp.auth.config.AuthenticationMode;
import com.company.incert.ocsp.auth.security.AuthenticationService;
import com.company.incert.ocsp.auth.security.ClientCertificateAuthFilter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Thin HTTP adapter for authentication configuration and login/session endpoints.
 * Delegates all authentication logic to {@link AuthenticationService}.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Admin authentication and session verification endpoints")
public class AuthController {

    private final AuthenticationService authenticationService;

    @Schema(description = "Credentials payload for username/password login")
    public record LoginPayload(
        @Schema(description = "Username", example = "admin") String username,
        @Schema(description = "Password") String password
    ) {}

    @Operation(summary = "Get active authentication configuration",
               description = "Returns auth mode, TLS status, and Keycloak coordinates. No secrets included.")
    @GetMapping("/api/v1/auth/config")
    public ResponseEntity<Map<String, Object>> getConfig() {
        return ResponseEntity.ok(authenticationService.getPublicAuthConfig());
    }

    @Operation(summary = "Check current authentication status",
               description = "Returns uniform InternalPrincipal identity (userId, username, roles, tenantId). No secrets.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User is authenticated"),
        @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    @GetMapping("/api/v1/auth/me")
    public ResponseEntity<Map<String, Object>> me(Authentication auth) {
        AuthenticationMode mode = authenticationService.resolvedMode();
        return authenticationService.inspectCurrentSession(auth)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                        "authenticated", false,
                        "authMode", mode.name(),
                        "message", "Not authenticated"
                )));
    }

    @Operation(summary = "Authenticate credentials",
               description = "Validates username/password against the users table or confirms a Keycloak Bearer session.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Authentication successful"),
        @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
    @PostMapping("/api/v1/auth/login")
    public ResponseEntity<Map<String, Object>> login(
            Authentication auth,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Login credentials", required = false)
            @RequestBody(required = false) LoginPayload payload) {

        AuthenticationMode mode = authenticationService.resolvedMode();
        String username = payload != null ? payload.username() : null;
        String password = payload != null ? payload.password() : null;

        return authenticationService.authenticate(auth, username, password)
                .map(ResponseEntity::ok)
                .orElseGet(() -> {
                    String failMsg = mode.isKeycloak()
                            ? "In KEYCLOAK mode sign in through Keycloak (Bearer token)"
                            : "Invalid username or password";
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                            "authenticated", false,
                            "authMode", mode.name(),
                            "message", failMsg
                    ));
                });
    }

    @Operation(summary = "Authenticate via mTLS client certificate",
               description = "Validates the browser-presented X.509 client certificate against hot-reloaded Trusted CAs and user_certificates, returning a Bearer JWT.")
    @PostMapping("/api/v1/auth/login/mtls")
    public ResponseEntity<Map<String, Object>> loginWithMtls(HttpServletRequest request) {
        AuthenticationMode mode = authenticationService.resolvedMode();
        X509Certificate cert = ClientCertificateAuthFilter.extractClientCertificate(request).orElse(null);
        return authenticationService.authenticateByClientCertificate(cert)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                        "authenticated", false,
                        "authMode", mode.name(),
                        "message", "No trusted, user-linked client certificate was presented. Please sign in with credentials or Keycloak."
                )));
    }
}
