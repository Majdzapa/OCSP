package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.AppSecurityProperties;
import com.company.incert.ocsp.config.KeycloakProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthControllerTest {

    private AuthController controller;

    @BeforeEach
    void setUp() {
        controller = newController("SELF_MANAGED");
    }

    private static AuthController newController(String authMode) {
        AppSecurityProperties security = new AppSecurityProperties();
        security.setAuthMode(authMode);
        security.getTls().setEnabled(true);

        KeycloakProperties keycloak = new KeycloakProperties();
        keycloak.setAuthServerUrl("http://localhost:8081");
        keycloak.setRealm("incert");
        keycloak.setClientId("ocsp-console");

        PasswordEncoder encoder = new BCryptPasswordEncoder();
        String encodedAdmin = encoder.encode("changeme");
        UserDetailsService uds = username -> {
            if ("admin".equals(username)) {
                return User.builder().username("admin").password(encodedAdmin).authorities("ROLE_ADMIN").build();
            }
            throw new UsernameNotFoundException("Not found: " + username);
        };

        return new AuthController(security, keycloak, uds, encoder);
    }

    @Test
    void getConfig_selfManaged_returnsSelfManagedConfig() {
        ResponseEntity<Map<String, Object>> response = controller.getConfig();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authMode", "SELF_MANAGED");
        assertThat(response.getBody()).containsEntry("isKeycloak", false);
        assertThat(response.getBody()).containsEntry("tlsEnabled", true);
        assertThat(response.getBody()).doesNotContainKey("basicAuth");
    }

    @Test
    void getConfig_legacyKeyclockAlias_resolvesToKeycloakMode() {
        var keycloakController = newController("KEYCLOCK");
        ResponseEntity<Map<String, Object>> response = keycloakController.getConfig();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
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
        assertThat(response.getBody()).doesNotContainKey("basicAuth");
    }

    @Test
    void login_withValidCredentials_returns200() {
        var payload = new AuthController.LoginPayload("admin", "changeme");
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("username", "admin");
        assertThat(response.getBody()).containsEntry("authType", "BASIC");
        assertThat(response.getBody()).doesNotContainKey("basicAuth");
    }

    @Test
    void login_withInvalidCredentials_returns401() {
        var payload = new AuthController.LoginPayload("admin", "wrongpassword");
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("authenticated", false);
    }
}
