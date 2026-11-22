package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.AdminProperties;
import com.company.incert.ocsp.config.AppSecurityProperties;
import com.company.incert.ocsp.config.AuthenticationMode;
import com.company.incert.ocsp.config.KeycloakProperties;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Authentication configuration and session endpoints.
 *
 * <p>Supports {@code KEYCLOAK} (OAuth2 / OIDC Bearer JWT) and {@code SELF_MANAGED}
 * (username & password). TLS is a deployment setting ({@code security.tls.enabled});
 * it is exposed read-only.
 *
 * <p>IMPORTANT: No credential values (passwords) are ever included in HTTP responses.
 */
@Slf4j
@RestController
@Tag(name = "Authentication", description = "Admin authentication and session verification endpoints")
public class AuthController {

    private final AppSecurityProperties securityProperties;
    private final AdminProperties adminProperties;
    private final KeycloakProperties keycloakProperties;

    @Autowired
    public AuthController(AppSecurityProperties securityProperties,
                          AdminProperties adminProperties,
                          KeycloakProperties keycloakProperties) {
        this.securityProperties = securityProperties;
        this.adminProperties = adminProperties;
        this.keycloakProperties = keycloakProperties;
    }

    @Schema(description = "Credentials payload for username/password login")
    public record LoginPayload(
        @Schema(description = "Admin username", example = "admin") String username,
        @Schema(description = "Admin password") String password
    ) {}

    // -------------------------------------------------------------------------
    // Public endpoints — readable by unauthenticated callers (safe metadata only)
    // -------------------------------------------------------------------------

    @Operation(summary = "Get active authentication configuration",
               description = "Returns auth mode, TLS status, and Keycloak coordinates. No secrets included.")
    @GetMapping("/api/v1/auth/config")
    public ResponseEntity<Map<String, Object>> getConfig() {
        AuthenticationMode mode = securityProperties.authenticationMode();
        Map<String, Object> body = Map.of(
            "authMode", mode.name(),
            "isKeycloak", mode.isKeycloak(),
            "tlsEnabled", securityProperties.getTls().isEnabled(),
            "keycloak", Map.of(
                "authServerUrl", keycloakProperties.effectivePublicUrl(),
                "realm", keycloakProperties.getRealm(),
                "clientId", keycloakProperties.getClientId()
            )
        );
        return ResponseEntity.ok(body);
    }

    @Operation(summary = "Check current authentication status",
               description = "Returns identity and roles of the authenticated session caller. No secrets.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User is authenticated"),
        @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    @GetMapping("/api/v1/auth/me")
    public ResponseEntity<Map<String, Object>> me(Authentication auth) {
        AuthenticationMode mode = securityProperties.authenticationMode();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "authenticated", false,
                "authMode", mode.name(),
                "message", "Not authenticated"
            ));
        }
        return ResponseEntity.ok(Map.of(
            "authenticated", true,
            "username", auth.getName(),
            "roles", auth.getAuthorities(),
            "authMode", mode.name(),
            "tlsEnabled", securityProperties.getTls().isEnabled()
        ));
    }

    @Operation(summary = "Authenticate admin credentials",
               description = "Validates username/password or Keycloak Bearer session and returns confirmation. No raw secrets in response.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Authentication successful"),
        @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
    @PostMapping("/api/v1/auth/login")
    public ResponseEntity<Map<String, Object>> login(
            Authentication auth,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Login credentials", required = false)
            @RequestBody(required = false) LoginPayload payload) {

        AuthenticationMode mode = securityProperties.authenticationMode();

        // 1. Already authenticated by Spring Security (HttpBasic / JWT Bearer)
        if (isAuthenticated(auth)) {
            return ok(mode, auth.getName(), "SESSION");
        }

        // 2. Username / password credential payload provided (in SELF_MANAGED mode)
        if (payload != null && !mode.isKeycloak() && isValidBasic(payload.username(), payload.password())) {
            return ok(mode, adminProperties.getUsername(), "BASIC");
        }

        log.warn("Authentication attempt failed: authMode={}", mode);
        String failMsg = mode.isKeycloak()
            ? "In KEYCLOAK mode sign in through Keycloak (Bearer token)"
            : "Invalid username or password";

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
            "authenticated", false,
            "authMode", mode.name(),
            "message", failMsg
        ));
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static boolean isAuthenticated(Authentication auth) {
        return auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal());
    }

    private boolean isValidBasic(String username, String password) {
        return username != null && password != null
            && adminProperties.getUsername().equals(username.trim())
            && adminProperties.getPassword().equals(password);
    }

    private ResponseEntity<Map<String, Object>> ok(AuthenticationMode mode, String username, String authType) {
        return ResponseEntity.ok(Map.of(
            "authenticated", true,
            "username", username,
            "authMode", mode.name(),
            "tlsEnabled", securityProperties.getTls().isEnabled(),
            "authType", authType
        ));
    }
}
