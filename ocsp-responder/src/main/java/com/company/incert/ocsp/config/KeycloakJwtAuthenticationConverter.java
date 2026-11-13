package com.company.incert.ocsp.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Extracts and maps roles and groups from Keycloak JWT tokens into Spring Security GrantedAuthorities.
 * Supports:
 * <ul>
 *   <li>{@code realm_access.roles}</li>
 *   <li>{@code resource_access.<client>.roles}</li>
 *   <li>{@code groups} (e.g. /ocsp-administrators -> ROLE_ADMIN)</li>
 *   <li>Direct {@code roles} claim</li>
 * </ul>
 */
public class KeycloakJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        // Helper to format role names cleanly
        java.util.function.Consumer<String> addRole = r -> {
            if (r == null || r.isBlank()) return;
            String normalized = r.trim().toUpperCase();
            if (!normalized.startsWith("ROLE_")) {
                normalized = "ROLE_" + normalized;
            }
            authorities.add(new SimpleGrantedAuthority(normalized));
        };

        // 1. Extract realm_access.roles
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        if (realmAccess != null && realmAccess.get("roles") instanceof Collection<?> roles) {
            for (Object role : roles) {
                addRole.accept(role.toString());
            }
        }

        // 2. Extract resource_access.<client>.roles
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess != null) {
            for (Object clientObj : resourceAccess.values()) {
                if (clientObj instanceof Map<?, ?> clientMap && clientMap.get("roles") instanceof Collection<?> roles) {
                    for (Object role : roles) {
                        addRole.accept(role.toString());
                    }
                }
            }
        }

        // 3. Extract direct roles claim if present
        if (jwt.getClaim("roles") instanceof Collection<?> roles) {
            for (Object role : roles) {
                addRole.accept(role.toString());
            }
        }

        // 4. Extract groups claim (e.g. ["/ocsp-administrators", "/ocsp-operators"])
        if (jwt.getClaim("groups") instanceof Collection<?> groups) {
            for (Object grp : groups) {
                String groupName = grp.toString().toLowerCase().replace("/", "").trim();
                if (groupName.contains("admin")) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                }
                if (groupName.contains("operator")) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_OPERATOR"));
                    authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                }
                if (groupName.contains("auditor")) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_AUDITOR"));
                }
            }
        }

        // 5. Default fallback if username or subject is "admin"
        String username = jwt.getClaimAsString("preferred_username");
        if (username == null) {
            username = jwt.getSubject();
        }
        if ("admin".equalsIgnoreCase(username)) {
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }

        return new JwtAuthenticationToken(jwt, authorities, username);
    }
}
