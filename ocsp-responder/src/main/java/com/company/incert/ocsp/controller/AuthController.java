package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.AuthenticationMode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.MessageDigest;
import java.util.Map;

/**
 * Authentication configuration and session endpoints.
 *
 * <p>The TLS toggle endpoint is intentionally restricted to authenticated
 * callers — it is mapped under {@code /api/v1/admin/**} in SecurityConfig.
 *
 * <p>IMPORTANT: No credential values (passwords, raw API keys) are ever
 * included in HTTP responses. The client uses its own token / session cookie
 * obtained through Spring Security filters; this controller only confirms
 * authentication status and returns safe metadata.
 */
@Slf4j
@RestController
@Tag(name = "Authentication", description = "Admin authentication and session verification endpoints")
public class AuthController {

    private final String authModeStr;
    private volatile boolean tlsEnabled;
    private final String adminUsername;
    private final String adminPassword;
    private final String adminApiKey;
    private final String keycloakAuthServerUrl;
    private final String keycloakRealm;
    private final String keycloakClientId;

    @Autowired
    public AuthController(
            @Value("${security.auth-mode:${auth.mode:SELF_MANAGED}}") String authModeStr,
            @Value("${security.tls.enabled:${auth.tls.enabled:${tls.enabled:true}}}") boolean tlsEnabled,
            @Value("${admin.username:admin}") String adminUsername,
            @Value("${admin.password:changeme}") String adminPassword,
            @Value("${admin.api-key:incert-admin-secret-key}") String adminApiKey,
            @Value("${keycloak.auth-server-url:http://localhost:8081}") String keycloakAuthServerUrl,
            @Value("${keycloak.realm:incert}") String keycloakRealm,
            @Value("${keycloak.client-id:ocsp-console}") String keycloakClientId) {
        this.authModeStr = authModeStr;
        this.tlsEnabled = tlsEnabled;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.adminApiKey = adminApiKey;
        this.keycloakAuthServerUrl = keycloakAuthServerUrl;
        this.keycloakRealm = keycloakRealm;
        this.keycloakClientId = keycloakClientId;
    }

    /** Constructor used by unit tests only — avoids Spring context. */
    AuthController(String authModeStr, boolean tlsEnabled,
                   String adminUsername, String adminPassword, String adminApiKey) {
        this(authModeStr, tlsEnabled, adminUsername, adminPassword, adminApiKey,
             "http://localhost:8081", "incert", "ocsp-console");
    }

    @Schema(description = "Credentials payload for login (supports username/password or API key)")
    public record LoginPayload(
        @Schema(description = "Admin username", example = "admin") String username,
        @Schema(description = "Admin password") String password,
        @Schema(description = "Admin API Key") String apiKey
    ) {}

    // -------------------------------------------------------------------------
    // Public endpoints — readable by unauthenticated callers (safe metadata only)
    // -------------------------------------------------------------------------

    @Operation(summary = "Get active authentication configuration",
               description = "Returns auth mode, TLS status, and Keycloak coordinates. No secrets included.")
    @GetMapping("/api/v1/auth/config")
    public ResponseEntity<Map<String, Object>> getConfig() {
        AuthenticationMode mode = AuthenticationMode.fromString(authModeStr);
        Map<String, Object> body = Map.of(
            "authMode", mode.name(),
            "isKeycloak", mode.isKeycloak(),
            "tlsEnabled", tlsEnabled,
            "keycloak", Map.of(
                "authServerUrl", keycloakAuthServerUrl,
                "realm", keycloakRealm,
                "clientId", keycloakClientId
            )
        );
        return ResponseEntity.ok(body);
    }

    @Operation(summary = "Get TLS status", description = "Returns whether TLS is currently active for OCSP login")
    @GetMapping("/api/v1/auth/tls")
    public ResponseEntity<Map<String, Object>> getTlsStatus() {
        return ResponseEntity.ok(Map.of(
            "tlsEnabled", tlsEnabled,
            "status", tlsEnabled ? "ACTIVE" : "DEACTIVATED"
        ));
    }

    @Operation(summary = "Check current authentication status",
               description = "Returns identity and roles of the authenticated session caller. No secrets.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User is authenticated"),
        @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    @GetMapping("/api/v1/auth/me")
    public ResponseEntity<Map<String, Object>> me(Authentication auth) {
        AuthenticationMode mode = AuthenticationMode.fromString(authModeStr);
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
            "tlsEnabled", tlsEnabled
        ));
    }

    @Operation(summary = "Authenticate admin credentials",
               description = "Validates credentials and returns a session confirmation. No raw secrets in response.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Authentication successful"),
        @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
    @PostMapping("/api/v1/auth/login")
    public ResponseEntity<Map<String, Object>> login(
            Authentication auth,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Login credentials", required = false)
            @RequestBody(required = false) LoginPayload payload) {

        AuthenticationMode mode = AuthenticationMode.fromString(authModeStr);

        // 1. Already authenticated by Spring Security (HttpBasic / ApiKeyFilter / JWT Bearer)
        if (isAuthenticated(auth)) {
            return ok(mode, auth.getName(), "SESSION");
        }

        // 2. Credential payload provided
        if (payload != null) {
            if (isValidApiKey(payload.apiKey())) {
                return ok(mode, "api-key-admin", "API_KEY");
            }
            if (!mode.isKeycloak() && isValidBasic(payload.username(), payload.password())) {
                return ok(mode, adminUsername, "BASIC");
            }
        }

        log.warn("Authentication attempt failed: authMode={}", mode);
        String failMsg = mode.isKeycloak()
            ? "In KEYCLOAK mode supply a valid Bearer token via Authorization header or API key via X-API-KEY header"
            : "Invalid username/password or API key";

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
            "authenticated", false,
            "authMode", mode.name(),
            "message", failMsg
        ));
    }

    // -------------------------------------------------------------------------
    // Admin-only endpoints — secured by Spring Security (ROLE_ADMIN required)
    // mapped under /api/v1/admin/** so SecurityConfig applies hasRole("ADMIN")
    // -------------------------------------------------------------------------

    @Operation(summary = "Toggle TLS for OCSP login", description = "Requires ROLE_ADMIN. Dynamically activate or deactivate TLS.")
    @PostMapping("/api/v1/admin/tls/ocsp-login/toggle")
    public ResponseEntity<Map<String, Object>> toggleTls(
            @RequestBody(required = false) Map<String, Boolean> body) {
        if (body != null && body.containsKey("enabled")) {
            this.tlsEnabled = Boolean.TRUE.equals(body.get("enabled"));
        } else {
            this.tlsEnabled = !this.tlsEnabled;
        }
        log.info("OCSP login TLS toggled to: {}", tlsEnabled);
        return ResponseEntity.ok(Map.of(
            "tlsEnabled", tlsEnabled,
            "status", tlsEnabled ? "ACTIVE" : "DEACTIVATED",
            "message", "OCSP login TLS updated to " + (tlsEnabled ? "ACTIVE" : "DEACTIVATED")
        ));
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static boolean isAuthenticated(Authentication auth) {
        return auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal());
    }

    /** Constant-time comparison to prevent timing-based API key enumeration. */
    private boolean isValidApiKey(String provided) {
        if (provided == null || provided.isBlank()) return false;
        return MessageDigest.isEqual(
            provided.trim().getBytes(),
            adminApiKey.getBytes()
        );
    }

    private boolean isValidBasic(String username, String password) {
        return username != null && password != null
            && adminUsername.equals(username.trim())
            && adminPassword.equals(password);
    }

    private ResponseEntity<Map<String, Object>> ok(AuthenticationMode mode, String username, String authType) {
        return ResponseEntity.ok(Map.of(
            "authenticated", true,
            "username", username,
            "authMode", mode.name(),
            "tlsEnabled", tlsEnabled,
            "authType", authType
        ));
    }
}
