package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.AppAuthProperties;
import com.company.incert.ocsp.config.AppSecurityProperties;
import com.company.incert.ocsp.config.AuthenticationMode;
import com.company.incert.ocsp.config.KeycloakProperties;
import com.company.incert.ocsp.security.InternalPrincipal;
import com.company.incert.ocsp.security.InternalUserDetails;
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
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Authentication configuration and session endpoints.
 * Produces a uniform {@link InternalPrincipal} view ({@code userId}, {@code username},
 * {@code roles}, {@code tenantId}) regardless of {@code app.auth.mode}.
 */
@Slf4j
@RestController
@Tag(name = "Authentication", description = "Admin authentication and session verification endpoints")
public class AuthController {

    private final AppAuthProperties authProperties;
    private final AppSecurityProperties securityProperties;
    private final KeycloakProperties keycloakProperties;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AuthController(AppAuthProperties authProperties,
                          AppSecurityProperties securityProperties,
                          KeycloakProperties keycloakProperties,
                          UserDetailsService userDetailsService,
                          PasswordEncoder passwordEncoder) {
        this.authProperties = authProperties;
        this.securityProperties = securityProperties;
        this.keycloakProperties = keycloakProperties;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Schema(description = "Credentials payload for username/password login")
    public record LoginPayload(
        @Schema(description = "Username", example = "admin") String username,
        @Schema(description = "Password") String password
    ) {}

    @Operation(summary = "Get active authentication configuration",
               description = "Returns auth mode, TLS status, and Keycloak coordinates. No secrets included.")
    @GetMapping("/api/v1/auth/config")
    public ResponseEntity<Map<String, Object>> getConfig() {
        AuthenticationMode mode = authProperties.resolvedMode();
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
               description = "Returns uniform InternalPrincipal identity (userId, username, roles, tenantId). No secrets.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "User is authenticated"),
        @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    @GetMapping("/api/v1/auth/me")
    public ResponseEntity<Map<String, Object>> me(Authentication auth) {
        AuthenticationMode mode = authProperties.resolvedMode();
        if (!isAuthenticated(auth)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "authenticated", false,
                "authMode", mode.name(),
                "message", "Not authenticated"
            ));
        }
        InternalPrincipal principal = InternalPrincipal.from(auth);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("authenticated", true);
        body.put("userId", principal.userId());
        body.put("username", principal.username());
        body.put("email", principal.email());
        body.put("fullName", principal.fullName());
        body.put("tenantId", principal.tenantId());
        body.put("authSource", principal.authSource().name());
        body.put("roles", principal.roles().stream().sorted().toList());
        body.put("authMode", mode.name());
        body.put("tlsEnabled", securityProperties.getTls().isEnabled());
        return ResponseEntity.ok(body);
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

        AuthenticationMode mode = authProperties.resolvedMode();

        if (isAuthenticated(auth)) {
            InternalPrincipal principal = InternalPrincipal.from(auth);
            return ok(mode, principal, "SESSION");
        }

        if (payload != null && !mode.isKeycloak() && payload.username() != null && payload.password() != null) {
            try {
                UserDetails user = userDetailsService.loadUserByUsername(payload.username().trim());
                if (user.isEnabled() && passwordEncoder.matches(payload.password(), user.getPassword())) {
                    InternalPrincipal principal = (user instanceof InternalUserDetails iud)
                            ? iud.getPrincipal()
                            : new InternalPrincipal(null, user.getUsername(), null, null, "default",
                                com.company.incert.ocsp.entity.AuthSource.LOCAL,
                                user.getAuthorities().stream().map(a -> a.getAuthority()).collect(java.util.stream.Collectors.toSet()));
                    return ok(mode, principal, "BASIC");
                }
            } catch (UsernameNotFoundException ignored) {
                // Fall through to 401
            }
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

    private static boolean isAuthenticated(Authentication auth) {
        return auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal());
    }

    private ResponseEntity<Map<String, Object>> ok(AuthenticationMode mode, InternalPrincipal principal, String authType) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("authenticated", true);
        body.put("userId", principal.userId());
        body.put("username", principal.username());
        body.put("tenantId", principal.tenantId());
        body.put("roles", principal.roles().stream().sorted().toList());
        body.put("authMode", mode.name());
        body.put("tlsEnabled", securityProperties.getTls().isEnabled());
        body.put("authType", authType);
        return ResponseEntity.ok(body);
    }
}
