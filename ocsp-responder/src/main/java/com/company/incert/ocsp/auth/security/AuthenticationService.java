package com.company.incert.ocsp.auth.security;

import com.company.incert.ocsp.auth.config.AppAuthProperties;
import com.company.incert.ocsp.shared.config.AppSecurityProperties;
import com.company.incert.ocsp.auth.config.AuthenticationMode;
import com.company.incert.ocsp.auth.config.KeycloakProperties;
import com.company.incert.ocsp.auth.service.UserCertificateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Isolated authentication service decoupling credential verification, mode resolution,
 * and OIDC/Basic session inspection from HTTP controllers and OCSP business services.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AppAuthProperties authProperties;
    private final AppSecurityProperties securityProperties;
    private final KeycloakProperties keycloakProperties;
    private final AuthenticationManager authenticationManager;
    private final LocalJwtTokenService localJwtTokenService;
    private final UserCertificateService userCertificateService;

    public AuthenticationMode resolvedMode() {
        return authProperties.resolvedMode();
    }

    public Map<String, Object> getPublicAuthConfig() {
        AuthenticationMode mode = resolvedMode();
        return Map.of(
                "authMode", mode.name(),
                "isKeycloak", mode.isKeycloak(),
                "tlsEnabled", securityProperties.getTls().isEnabled(),
                "clientCertAuthEnabled", securityProperties.getTls().isClientCertAuthEnabled(),
                "keycloak", Map.of(
                        "authServerUrl", keycloakProperties.effectivePublicUrl(),
                        "realm", keycloakProperties.getRealm(),
                        "clientId", keycloakProperties.getClientId()
                )
        );
    }

    public Optional<Map<String, Object>> inspectCurrentSession(Authentication auth) {
        if (!isAuthenticated(auth)) {
            return Optional.empty();
        }
        AuthenticationMode mode = resolvedMode();
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
        return Optional.of(body);
    }

    public Optional<Map<String, Object>> authenticate(Authentication existingAuth, String username, String password) {
        AuthenticationMode mode = resolvedMode();
        if (isAuthenticated(existingAuth)) {
            return Optional.of(buildSuccessPayload(mode, InternalPrincipal.from(existingAuth), "SESSION"));
        }
        if (!mode.isKeycloak() && username != null && password != null) {
            try {
                Authentication authenticated = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(username.trim(), password));
                InternalPrincipal principal = InternalPrincipal.from(authenticated);
                String accessToken = localJwtTokenService.issueToken(principal);
                Map<String, Object> payload = buildSuccessPayload(mode, principal, "BEARER");
                payload.put("accessToken", accessToken);
                payload.put("tokenType", "Bearer");
                payload.put("expiresIn", localJwtTokenService.expiresInSeconds());
                return Optional.of(payload);
            } catch (AuthenticationException ignored) {
                // Fall through to failure
            }
        }
        log.warn("Authentication attempt failed: authMode={}", mode);
        return Optional.empty();
    }

    public Optional<Map<String, Object>> authenticateByClientCertificate(X509Certificate clientCert) {
        if (!securityProperties.getTls().isClientCertAuthEnabled() || clientCert == null) {
            return Optional.empty();
        }
        AuthenticationMode mode = resolvedMode();
        return userCertificateService.authenticateByClientCertificate(clientCert).map(principal -> {
            String accessToken = localJwtTokenService.issueToken(principal);
            Map<String, Object> payload = buildSuccessPayload(mode, principal, "MTLS");
            payload.put("accessToken", accessToken);
            payload.put("tokenType", "Bearer");
            payload.put("expiresIn", localJwtTokenService.expiresInSeconds());
            return payload;
        });
    }

    public static boolean isAuthenticated(Authentication auth) {
        return auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal());
    }

    private Map<String, Object> buildSuccessPayload(AuthenticationMode mode, InternalPrincipal principal, String authType) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("authenticated", true);
        body.put("userId", principal.userId());
        body.put("username", principal.username());
        body.put("tenantId", principal.tenantId());
        body.put("roles", principal.roles().stream().sorted().toList());
        body.put("authMode", mode.name());
        body.put("tlsEnabled", securityProperties.getTls().isEnabled());
        body.put("authType", authType);
        return body;
    }
}

