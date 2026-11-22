package com.company.incert.ocsp.auth.config;

import com.company.incert.ocsp.auth.entity.RoleEntity;
import com.company.incert.ocsp.auth.entity.UserEntity;
import com.company.incert.ocsp.auth.security.InternalPrincipal;
import com.company.incert.ocsp.auth.service.KeycloakSyncService;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Extracts coarse roles from Keycloak JWT tokens, performs JIT provisioning/refresh
 * in the local DB replica via {@link KeycloakSyncService} (keyed by {@code sub}),
 * and produces a uniform {@link InternalPrincipal} containing {@code userId}, {@code roles},
 * and {@code tenantId}.
 */
public class KeycloakJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final KeycloakSyncService syncService;

    public KeycloakJwtAuthenticationConverter() {
        this.syncService = null;
    }

    public KeycloakJwtAuthenticationConverter(KeycloakSyncService syncService) {
        this.syncService = syncService;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Set<String> tokenRoles = new HashSet<>();

        java.util.function.Consumer<String> addRole = r -> {
            if (r == null || r.isBlank()) return;
            String normalized = r.trim().toUpperCase();
            if (!normalized.startsWith("ROLE_")) {
                normalized = "ROLE_" + normalized;
            }
            tokenRoles.add(normalized);
        };

        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null && realmAccess.get("roles") instanceof Collection<?> roles) {
            for (Object role : roles) addRole.accept(role.toString());
        }

        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null) {
            for (Object clientObj : resourceAccess.values()) {
                if (clientObj instanceof Map<?, ?> clientMap && clientMap.get("roles") instanceof Collection<?> roles) {
                    for (Object role : roles) addRole.accept(role.toString());
                }
            }
        }

        if (jwt.getClaim("roles") instanceof Collection<?> roles) {
            for (Object role : roles) addRole.accept(role.toString());
        }

        if (jwt.getClaim("groups") instanceof Collection<?> groups) {
            for (Object grp : groups) {
                String groupName = grp.toString().toLowerCase().replace("/", "").trim();
                if (groupName.contains("admin")) tokenRoles.add("ROLE_ADMIN");
                if (groupName.contains("agent") || groupName.contains("operator")) tokenRoles.add("ROLE_AGENT");
                if (groupName.contains("auditor")) tokenRoles.add("ROLE_AUDITOR");
            }
        }

        String username = jwt.getClaimAsString("preferred_username");
        if (username == null) username = jwt.getSubject();
        if ("admin".equalsIgnoreCase(username)) {
            tokenRoles.add("ROLE_ADMIN");
        }

        String email = jwt.getClaimAsString("email");
        boolean emailVerified = Boolean.TRUE.equals(jwt.getClaim("email_verified"));
        String fullName = jwt.getClaimAsString("name");

        InternalPrincipal principal;
        if (syncService != null && jwt.getSubject() != null) {
            UserEntity user = syncService.upsertFromTokenClaims(
                    jwt.getSubject(), username, email, emailVerified, fullName, tokenRoles);
            Set<String> dbRoles = user.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toSet());
            Set<String> combinedRoles = new HashSet<>(tokenRoles);
            combinedRoles.addAll(dbRoles);
            principal = new InternalPrincipal(
                    user.getId(),
                    user.getUsername(),
                    user.getEmail(),
                    user.getFullName(),
                    user.getTenantId(),
                    user.getAuthSource(),
                    combinedRoles
            );
        } else {
            principal = new InternalPrincipal(
                    jwt.getSubject(), username, email, fullName, "default",
                    com.company.incert.ocsp.auth.entity.AuthSource.KEYCLOAK, tokenRoles);
        }

        Collection<GrantedAuthority> authorities = principal.roles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        return new AbstractAuthenticationToken(authorities) {
            {
                setAuthenticated(true);
            }

            @Override
            public Object getCredentials() {
                return jwt;
            }

            @Override
            public Object getPrincipal() {
                return principal;
            }
        };
    }
}
