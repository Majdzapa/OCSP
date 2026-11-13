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
    void me_unauthenticated_returns401() {
        ResponseEntity<Map<String, Object>> response = controller.me(null);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("authenticated", false);
    }

    @Test
    void me_authenticated_returnsUsername() {
        var auth = new UsernamePasswordAuthenticationToken(
                "admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        ResponseEntity<Map<String, Object>> response = controller.me(auth);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "admin");
    }

    @Test
    void login_withValidCredentials_returns200() {
        var payload = new AuthController.LoginPayload("admin", "changeme", null);
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "admin");
        assertThat(response.getBody()).containsKey("basicAuth");
    }

    @Test
    void login_withValidApiKey_returns200() {
        var payload = new AuthController.LoginPayload(null, null, "incert-admin-secret-key");
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "api-key-admin");
        assertThat(response.getBody()).containsEntry("apiKey", "incert-admin-secret-key");
    }

    @Test
    void login_withInvalidCredentials_returns401() {
        var payload = new AuthController.LoginPayload("admin", "wrongpassword", null);
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("authenticated", false);
    }
}

