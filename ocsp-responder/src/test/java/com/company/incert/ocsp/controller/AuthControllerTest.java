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
        controller = new AuthController("admin", "changeme", "incert-admin-secret-key");
    }

    @Test
    void getConfig_selfManaged_returnsSelfManagedConfig() {
        ResponseEntity<Map<String, Object>> response = controller.getConfig();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authMode", "SELF_MANAGED");
        assertThat(response.getBody()).containsEntry("isKeycloak", false);
    }

    @Test
    void getConfig_keyclock_returnsKeyclockConfig() {
        var keycloakController = new AuthController(
                "KEYCLOCK", "admin", "changeme", "incert-admin-secret-key",
                "http://localhost:8081", "incert", "ocsp-console");
        ResponseEntity<Map<String, Object>> response = keycloakController.getConfig();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authMode", "KEYCLOCK");
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
    void me_authenticated_returnsUsername() {
        var auth = new UsernamePasswordAuthenticationToken(
                "admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        ResponseEntity<Map<String, Object>> response = controller.me(auth);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "admin");
        assertThat(response.getBody()).containsEntry("authMode", "SELF_MANAGED");
    }

    @Test
    void login_withValidCredentials_returns200() {
        var payload = new AuthController.LoginPayload("admin", "changeme", null, null);
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "admin");
        assertThat(response.getBody()).containsKey("basicAuth");
    }

    @Test
    void login_withValidApiKey_returns200() {
        var payload = new AuthController.LoginPayload(null, null, "incert-admin-secret-key", null);
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "api-key-admin");
        assertThat(response.getBody()).containsEntry("apiKey", "incert-admin-secret-key");
    }

    @Test
    void login_withInvalidCredentials_returns401() {
        var payload = new AuthController.LoginPayload("admin", "wrongpassword", null, null);
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("authenticated", false);
    }

    @Test
    void login_keyclockMode_withToken_returns200() {
        var keycloakController = new AuthController(
                "KEYCLOCK", "admin", "changeme", "incert-admin-secret-key",
                "http://localhost:8081", "incert", "ocsp-console");
        var payload = new AuthController.LoginPayload(null, null, null, "jwt.token.here");
        ResponseEntity<Map<String, Object>> response = keycloakController.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("authType", "BEARER");
        assertThat(response.getBody()).containsEntry("token", "jwt.token.here");
    }
}
