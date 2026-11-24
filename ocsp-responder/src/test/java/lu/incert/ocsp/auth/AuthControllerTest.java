package lu.incert.ocsp.auth;


import lu.incert.ocsp.auth.controller.AuthController;
import lu.incert.ocsp.auth.config.AppAuthProperties;
import lu.incert.ocsp.shared.config.AppSecurityProperties;
import lu.incert.ocsp.auth.config.KeycloakProperties;
import lu.incert.ocsp.auth.entity.AuthSource;
import lu.incert.ocsp.auth.security.AuthenticationService;
import lu.incert.ocsp.auth.security.InternalPrincipal;
import lu.incert.ocsp.auth.security.InternalUserDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AuthControllerTest {

    private AuthController controller;

    @BeforeEach
    void setUp() {
        controller = newController("SELF_MANAGEMENT");
    }

    private static AuthController newController(String authMode) {
        AppAuthProperties authProps = new AppAuthProperties();
        authProps.setMode(authMode);
        authProps.getJwt().setSecret("unit-test-jwt-secret-key-at-least-32-bytes");

        AppSecurityProperties security = new AppSecurityProperties();
        security.getTls().setEnabled(true);

        KeycloakProperties keycloak = new KeycloakProperties();
        keycloak.setAuthServerUrl("http://localhost:8081");
        keycloak.setRealm("incert");
        keycloak.setClientId("ocsp-console");

        PasswordEncoder encoder = new BCryptPasswordEncoder();
        String encodedAdmin = encoder.encode("changeme");
        UserDetailsService uds = username -> {
            if ("admin".equals(username)) {
                var principal = new InternalPrincipal(
                        "uuid-admin-1", "admin", "admin@incert.local", "Incert Admin",
                        "default", AuthSource.LOCAL, Set.of("ROLE_ADMIN"));
                return new InternalUserDetails(principal, encodedAdmin, true);
            }
            throw new UsernameNotFoundException("Not found: " + username);
        };

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(uds);
        provider.setPasswordEncoder(encoder);
        AuthenticationManager authManager = new ProviderManager(provider);
        var jwtService = new lu.incert.ocsp.auth.security.LocalJwtTokenService(authProps);
        var userCertService = org.mockito.Mockito.mock(lu.incert.ocsp.auth.service.UserCertificateService.class);

        return new AuthController(new AuthenticationService(authProps, security, keycloak, authManager, jwtService, userCertService));
    }

    @Test
    void getConfig_selfManagement_returnsSelfManagementConfig() {
        ResponseEntity<Map<String, Object>> response = controller.getConfig();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authMode", "SELF_MANAGEMENT");
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
        assertThat(response.getBody()).containsEntry("authMode", "SELF_MANAGEMENT");
    }

    @Test
    void me_authenticated_returnsUniformPrincipalWithoutSecrets() {
        var principal = new InternalPrincipal(
                "uuid-admin-1", "admin", "admin@incert.local", "Incert Admin",
                "default", AuthSource.LOCAL, Set.of("ROLE_ADMIN"));
        var auth = new UsernamePasswordAuthenticationToken(
                principal, null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        ResponseEntity<Map<String, Object>> response = controller.me(auth);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("userId", "uuid-admin-1");
        assertThat(response.getBody()).containsEntry("username", "admin");
        assertThat(response.getBody()).containsEntry("tenantId", "default");
        assertThat(response.getBody()).doesNotContainKey("basicAuth");
    }

    @Test
    void login_withValidCredentials_returns200() {
        var payload = new AuthController.LoginPayload("admin", "changeme");
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsEntry("authenticated", true);
        assertThat(response.getBody()).containsEntry("userId", "uuid-admin-1");
        assertThat(response.getBody()).containsEntry("username", "admin");
        assertThat(response.getBody()).containsEntry("authType", "BEARER");
        assertThat(response.getBody()).containsEntry("tokenType", "Bearer");
        assertThat(response.getBody().get("accessToken")).isInstanceOf(String.class).asString().isNotBlank();
    }

    @Test
    void login_withInvalidCredentials_returns401() {
        var payload = new AuthController.LoginPayload("admin", "wrongpassword");
        ResponseEntity<Map<String, Object>> response = controller.login(null, payload);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).containsEntry("authenticated", false);
    }
}
