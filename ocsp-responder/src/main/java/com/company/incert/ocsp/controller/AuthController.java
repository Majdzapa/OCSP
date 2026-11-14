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

    public AuthController(String adminUsername, String adminPassword, String adminApiKey) {
        this("SELF_MANAGED", true, adminUsername, adminPassword, adminApiKey, "http://localhost:8081", "incert", "ocsp-console");
    }

    public AuthController(String authModeStr, String adminUsername, String adminPassword, String adminApiKey) {
        this(authModeStr, true, adminUsername, adminPassword, adminApiKey, "http://localhost:8081", "incert", "ocsp-console");
    }

    public AuthController(String authModeStr, String adminUsername, String adminPassword, String adminApiKey,
                          String keycloakAuthServerUrl, String keycloakRealm, String keycloakClientId) {
        this(authModeStr, true, adminUsername, adminPassword, adminApiKey, keycloakAuthServerUrl, keycloakRealm, keycloakClientId);
    }

    public AuthController(String authModeStr, boolean tlsEnabled, String adminUsername, String adminPassword, String adminApiKey) {
        this(authModeStr, tlsEnabled, adminUsername, adminPassword, adminApiKey, "http://localhost:8081", "incert", "ocsp-console");
    }

    @Schema(description = "Credentials payload for login (supports username/password, X-API-KEY, Keycloak Bearer token, or mTLS Client Certificate)")
    public record LoginPayload(
        @Schema(description = "Admin username", example = "admin") String username,
        @Schema(description = "Admin password", example = "changeme") String password,
        @Schema(description = "Admin API Key", example = "incert-admin-secret-key") String apiKey,
        @Schema(description = "OAuth2 / Keycloak Bearer token", example = "eyJhbGciOiJSUzI1NiIsIn...") String token,
        @Schema(description = "PEM encoded client certificate or subject for mTLS authentication", example = "-----BEGIN CERTIFICATE-----\n...") String clientCert
    ) {
        public LoginPayload(String username, String password, String apiKey, String token) {
            this(username, password, apiKey, token, null);
        }
    }

    @Operation(summary = "Get active authentication configuration", description = "Returns active auth mode (SELF_MANAGED or KEYCLOCK), TLS activation status, and Keycloak details if applicable")
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
            "tlsEnabled", tlsEnabled,
            "keycloak", keycloakConfig
        ));
    }

    @Operation(summary = "Get TLS status for login", description = "Returns whether TLS is currently activated for OCSP login")
    @GetMapping("/tls")
    public ResponseEntity<Map<String, Object>> getTlsStatus() {
        return ResponseEntity.ok(Map.of(
            "tlsEnabled", tlsEnabled,
            "status", tlsEnabled ? "ACTIVE" : "DEACTIVATED"
        ));
    }

    @Operation(summary = "Activate or deactivate TLS for login", description = "Updates whether TLS authentication is active for OCSP login")
    @PostMapping("/tls")
    public ResponseEntity<Map<String, Object>> setTlsStatus(@RequestBody(required = false) Map<String, Boolean> body) {
        if (body != null && body.containsKey("enabled")) {
            this.tlsEnabled = Boolean.TRUE.equals(body.get("enabled"));
        }
        return ResponseEntity.ok(Map.of(
            "tlsEnabled", tlsEnabled,
            "status", tlsEnabled ? "ACTIVE" : "DEACTIVATED",
            "message", "OCSP login TLS status updated to " + (tlsEnabled ? "ACTIVE" : "DEACTIVATED")
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
                "tlsEnabled", tlsEnabled,
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

    @Operation(summary = "Authenticate admin credentials", description = "Validates username/password, API key, Keycloak token, or client certificate and returns authentication details")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Authentication successful"),
        @ApiResponse(responseCode = "400", description = "TLS authentication deactivated"),
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
                "tlsEnabled", tlsEnabled,
                "apiKey", adminApiKey,
                "basicAuth", basicHeader
            ));
        }

        // 2. If credentials provided in JSON body
        if (payload != null) {
            // Check Client Certificate authentication (mTLS)
            if (payload.clientCert() != null && !payload.clientCert().isBlank()) {
                if (!tlsEnabled) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                        "authenticated", false,
                        "authMode", mode.name(),
                        "tlsEnabled", false,
                        "message", "TLS authentication is currently deactivated in application configuration"
                    ));
                }

                String cert = payload.clientCert().trim();
                String certUser = "tls-admin-client";
                if (cert.contains("CN=")) {
                    int start = cert.indexOf("CN=") + 3;
                    int end = cert.indexOf(",", start);
                    if (end == -1) end = cert.indexOf("\n", start);
                    if (end == -1) end = cert.indexOf("/", start);
                    if (end == -1) end = cert.length();
                    certUser = cert.substring(start, end).trim();
                }

                return ResponseEntity.ok(Map.of(
                    "authenticated", true,
                    "username", certUser,
                    "roles", java.util.List.of("ROLE_ADMIN"),
                    "authMode", mode.name(),
                    "tlsEnabled", true,
                    "apiKey", adminApiKey,
                    "authType", "TLS_CLIENT_CERT"
                ));
            }

            // Check API Key (supported in both SELF_MANAGED and KEYCLOCK modes)
            if (payload.apiKey() != null && !payload.apiKey().isBlank()) {
                if (adminApiKey.equals(payload.apiKey().trim())) {
                    return ResponseEntity.ok(Map.of(
                        "authenticated", true,
                        "username", "api-key-admin",
                        "authMode", mode.name(),
                        "tlsEnabled", tlsEnabled,
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
                            "tlsEnabled", tlsEnabled,
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
                        "tlsEnabled", tlsEnabled,
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
            "tlsEnabled", tlsEnabled,
            "message", failMsg
        ));
    }
}
