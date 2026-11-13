package com.company.incert.ocsp.controller;

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
public class AuthController {

    private final String adminUsername;
    private final String adminPassword;
    private final String adminApiKey;

    public AuthController(
            @Value("${admin.username:admin}") String adminUsername,
            @Value("${admin.password:changeme}") String adminPassword,
            @Value("${admin.api-key:incert-admin-secret-key}") String adminApiKey) {
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.adminApiKey = adminApiKey;
    }

    public record LoginPayload(String username, String password, String apiKey) {}

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(Authentication auth) {
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "authenticated", false,
                "message", "Not authenticated"
            ));
        }
        return ResponseEntity.ok(Map.of(
            "authenticated", true,
            "username", auth.getName(),
            "roles", auth.getAuthorities()
        ));
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            Authentication auth,
            @RequestBody(required = false) LoginPayload payload) {

        // 1. If already authenticated via HttpBasic or ApiKeyAuthFilter
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            String basicHeader = "Basic " + Base64.getEncoder().encodeToString(
                    (adminUsername + ":" + adminPassword).getBytes(StandardCharsets.UTF_8));
            return ResponseEntity.ok(Map.of(
                "authenticated", true,
                "username", auth.getName(),
                "roles", auth.getAuthorities(),
                "apiKey", adminApiKey,
                "basicAuth", basicHeader
            ));
        }

        // 2. If credentials provided in JSON body
        if (payload != null) {
            // Check API Key
            if (payload.apiKey() != null && !payload.apiKey().isBlank()) {
                if (adminApiKey.equals(payload.apiKey().trim())) {
                    return ResponseEntity.ok(Map.of(
                        "authenticated", true,
                        "username", "api-key-admin",
                        "apiKey", adminApiKey,
                        "authType", "API_KEY"
                    ));
                }
            }

            // Check Username / Password
            if (payload.username() != null && payload.password() != null) {
                if (adminUsername.equals(payload.username().trim()) && adminPassword.equals(payload.password())) {
                    String basicHeader = "Basic " + Base64.getEncoder().encodeToString(
                            (adminUsername + ":" + adminPassword).getBytes(StandardCharsets.UTF_8));
                    return ResponseEntity.ok(Map.of(
                        "authenticated", true,
                        "username", adminUsername,
                        "apiKey", adminApiKey,
                        "basicAuth", basicHeader,
                        "authType", "BASIC"
                    ));
                }
            }
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
            "authenticated", false,
            "message", "Invalid username/password or API key"
        ));
    }
}
