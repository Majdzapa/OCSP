package com.company.incert.ocsp.controller;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthControllerTest {

    private AuthController controller;

    @BeforeEach
    void setUp() {
        controller = new AuthController("SELF_MANAGED", true, "admin", "changeme", "incert-admin-secret-key",
                "http://localhost:8081", "incert", "ocsp-console");
    }

    @Test
    void getConfig_selfManaged_returnsSelfManagedConfig() {
        ResponseEntity<Map<String, Object>> response = controller.getConfig();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authMode", "SELF_MANAGED");
        assertThat(response.getBody()).containsEntry("isKeycloak", false);
        assertThat(response.getBody()).containsEntry("tlsEnabled", true);
        // No secrets in response
        assertThat(response.getBody()).doesNotContainKey("apiKey");
        assertThat(response.getBody()).doesNotContainKey("basicAuth");
    }

    @Test
    void getConfig_legacyKeyclockAlias_resolvesToKeycloakMode() {
        // "KEYCLOCK" (legacy typo) must be normalised to the canonical KEYCLOAK enum.
        var keycloakController = new AuthController(
                "KEYCLOCK", true, "admin", "changeme", "incert-admin-secret-key",
                "http://localhost:8081", "incert", "ocsp-console");
        ResponseEntity<Map<String, Object>> response = keycloakController.getConfig();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        // AuthenticationMode.fromString("KEYCLOCK") returns KEYCLOAK (canonical name)
        assertThat(response.getBody()).containsEntry("authMode", "KEYCLOAK");
        assertThat(response.getBody()).containsEntry("isKeycloak", true);
        @SuppressWarnings("unchecked")
        Map<String, Object> keycloakMap = (Map<String, Object>) response.getBody().get("keycloak");
        assertThat(keycloakMap).containsEntry("authServerUrl", "http://localhost:8081");
        assertThat(keycloakMap).containsEntry("realm", "incert");
        assertThat(keycloakMap).containsEntry("clientId", "ocsp-console");
    }

    @Test
    void me_unauthenticated_returns401() {
        ResponseEntity<Map<String, Object>> response = controller.me(null);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("authenticated", false);
        assertThat(response.getBody()).containsEntry("authMode", "SELF_MANAGED");
    }

    @Test
    void me_authenticated_returnsUsernameWithoutSecrets() {
        var auth = new UsernamePasswordAuthenticationToken(
                "admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        ResponseEntity<Map<String, Object>> response = controller.me(auth);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "admin");
        assertThat(response.getBody()).containsEntry("authMode", "SELF_MANAGED");
        // Must not leak secrets
        assertThat(response.getBody()).doesNotContainKey("apiKey");
        assertThat(response.getBody()).doesNotContainKey("basicAuth");
    }

    @Test
    void login_alreadyAuthenticated_returns200WithoutSecrets() {
        var auth = new UsernamePasswordAuthenticationToken(
                "admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        ResponseEntity<Map<String, Object>> response = controller.login(auth, null);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "admin");
        // No raw secrets in response
        assertThat(response.getBody()).doesNotContainKey("apiKey");
        assertThat(response.getBody()).doesNotContainKey("basicAuth");
    }

    @Test
    void login_withValidCredentials_returns200() {
        var payload = new AuthController.LoginPayload("admin", "changeme", null);
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "admin");
        assertThat(response.getBody()).containsEntry("authType", "BASIC");
        // No raw secrets
        assertThat(response.getBody()).doesNotContainKey("apiKey");
        assertThat(response.getBody()).doesNotContainKey("basicAuth");
    }

    @Test
    void login_withValidApiKey_returns200() {
        var payload = new AuthController.LoginPayload(null, null, "incert-admin-secret-key");
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "api-key-admin");
        assertThat(response.getBody()).containsEntry("authType", "API_KEY");
        // No raw secrets
        assertThat(response.getBody()).doesNotContainKey("apiKey");
    }

    @Test
    void login_withInvalidCredentials_returns401() {
        var payload = new AuthController.LoginPayload("admin", "wrongpassword", null);
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("authenticated", false);
    }

    @Test
    void login_withInvalidApiKey_returns401() {
        var payload = new AuthController.LoginPayload(null, null, "wrong-key");
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("authenticated", false);
    }
}
