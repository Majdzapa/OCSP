package com.company.incert.ocsp.auth.security;

import com.company.incert.ocsp.auth.entity.AuthSource;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Uniform internal principal produced by BOTH {@code SELF_MANAGEMENT} and {@code KEYCLOAK} modes.
 * Business code always reads {@code userId}, {@code roles}, and {@code tenantId} from this principal
 * and never checks {@code app.auth.mode}.
 */
public record InternalPrincipal(
    String userId,
    String username,
    String email,
    String fullName,
    String tenantId,
    AuthSource authSource,
    Set<String> roles
) implements AuthenticatedPrincipal {

    @Override
    public String getName() {
        return username;
    }

    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }

    public static InternalPrincipal from(Authentication auth) {
        if (auth == null) {
            return null;
        }
        Object principal = auth.getPrincipal();
        if (principal instanceof InternalPrincipal ip) {
            return ip;
        }
        if (principal instanceof InternalUserDetails iud) {
            return iud.getPrincipal();
        }
        Set<String> authRoles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        return new InternalPrincipal(null, auth.getName(), null, null, "default", AuthSource.LOCAL, authRoles);
    }
}

