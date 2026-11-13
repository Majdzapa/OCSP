package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.AuthenticationMode;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Admin authentication and session verification endpoints")
public class AuthController {

    private final String authModeStr;
    private final String adminUsername;
    private final String adminPassword;
    private final String adminApiKey;
    private final String keycloakAuthServerUrl;
    private final String keycloakRealm;
    private final String keycloakClientId;

    @Autowired
    public AuthController(
            @Value("${security.auth-mode:${auth.mode:SELF_MANAGED}}") String authModeStr,
            @Value("${admin.username:admin}") String adminUsername,
            @Value("${admin.password:changeme}") String adminPassword,
            @Value("${admin.api-key:incert-admin-secret-key}") String adminApiKey,
            @Value("${keycloak.auth-server-url:http://localhost:8081}") String keycloakAuthServerUrl,
            @Value("${keycloak.realm:incert}") String keycloakRealm,
            @Value("${keycloak.client-id:ocsp-console}") String keycloakClientId) {
        this.authModeStr = authModeStr;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.adminApiKey = adminApiKey;
        this.keycloakAuthServerUrl = keycloakAuthServerUrl;
        this.keycloakRealm = keycloakRealm;
        this.keycloakClientId = keycloakClientId;
    }

    public AuthController(String adminUsername, String adminPassword, String adminApiKey) {
        this("SELF_MANAGED", adminUsername, adminPassword, adminApiKey, "http://localhost:8081", "incert", "ocsp-console");
    }

    @Schema(description = "Credentials payload for login (supports username/password, X-API-KEY, or Keycloak Bearer token)")
    public record LoginPayload(
        @Schema(description = "Admin username", example = "admin") String username,
        @Schema(description = "Admin password", example = "changeme") String password,
        @Schema(description = "Admin API Key", example = "incert-admin-secret-key") String apiKey,
        @Schema(description = "OAuth2 / Keycloak Bearer token", example = "eyJhbGciOiJSUzI1NiIsIn...") String token
    ) {}

    @Operation(summary = "Get active authentication configuration", description = "Returns active auth mode (SELF_MANAGED or KEYCLOCK) and Keycloak details if applicable")
    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getConfig() {
        AuthenticationMode mode = AuthenticationMode.fromString(authModeStr);
        Map<String, Object> keycloakConfig = Map.of(
            "authServerUrl", keycloakAuthServerUrl,
            "realm", keycloakRealm,
            "clientId", keycloakClientId
        );
        return ResponseEntity.ok(Map.of(
            "authMode", mode.name(),
            "isKeycloak", mode.isKeycloak(),
            "keycloak", keycloakConfig
        ));
    }

    @Operation(summary = "Check current authentication status", description = "Returns identity and roles of the authenticated session caller")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User is authenticated"),
        @ApiResponse(responseCode = "401", description = "Caller is not authenticated")
    })
    @GetMapping("/me")
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
            "authMode", mode.name()
        ));
    }

    @Operation(summary = "Authenticate admin credentials", description = "Validates username/password, API key, or Keycloak token and returns authentication details")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Authentication successful"),
        @ApiResponse(responseCode = "401", description = "Invalid credentials or token")
    })
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            Authentication auth,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(description = "Login credentials", required = false)
            @RequestBody(required = false) LoginPayload payload) {

        AuthenticationMode mode = AuthenticationMode.fromString(authModeStr);

        // 1. If already authenticated via HttpBasic, ApiKeyAuthFilter, or Jwt (Bearer)
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            String basicHeader = "Basic " + Base64.getEncoder().encodeToString(
                    (adminUsername + ":" + adminPassword).getBytes(StandardCharsets.UTF_8));
            return ResponseEntity.ok(Map.of(
                "authenticated", true,
                "username", auth.getName(),
                "roles", auth.getAuthorities(),
                "authMode", mode.name(),
                "apiKey", adminApiKey,
                "basicAuth", basicHeader
            ));
        }

        // 2. If credentials provided in JSON body
        if (payload != null) {
            // Check API Key (supported in both SELF_MANAGED and KEYCLOCK modes)
            if (payload.apiKey() != null && !payload.apiKey().isBlank()) {
                if (adminApiKey.equals(payload.apiKey().trim())) {
                    return ResponseEntity.ok(Map.of(
                        "authenticated", true,
                        "username", "api-key-admin",
                        "authMode", mode.name(),
                        "apiKey", adminApiKey,
                        "authType", "API_KEY"
                    ));
                }
            }

            // In SELF_MANAGED mode: check username / password
            if (!mode.isKeycloak()) {
                if (payload.username() != null && payload.password() != null) {
                    if (adminUsername.equals(payload.username().trim()) && adminPassword.equals(payload.password())) {
                        String basicHeader = "Basic " + Base64.getEncoder().encodeToString(
                                (adminUsername + ":" + adminPassword).getBytes(StandardCharsets.UTF_8));
                        return ResponseEntity.ok(Map.of(
                            "authenticated", true,
                            "username", adminUsername,
                            "authMode", mode.name(),
                            "apiKey", adminApiKey,
                            "basicAuth", basicHeader,
                            "authType", "BASIC"
                        ));
                    }
                }
            } else {
                // In KEYCLOCK mode: if token provided in payload, return Bearer auth
                if (payload.token() != null && !payload.token().isBlank()) {
                    return ResponseEntity.ok(Map.of(
                        "authenticated", true,
                        "username", "keycloak-user",
                        "authMode", mode.name(),
                        "token", payload.token().trim(),
                        "authType", "BEARER"
                    ));
                }
            }
        }

        String failMsg = mode.isKeycloak()
            ? "Authentication failed: in KEYCLOCK mode, supply a valid Bearer token or API key"
            : "Invalid username/password or API key";

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
            "authenticated", false,
            "authMode", mode.name(),
            "message", failMsg
        ));
    }
}
