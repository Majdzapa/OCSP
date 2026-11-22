package com.company.incert.ocsp.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Clean boundary for business/admin controllers to read the uniform {@link InternalPrincipal}
 * without depending on credential verification or Spring Security internals.
 */
@Component
public class CurrentUserProvider {

    public Optional<InternalPrincipal> getCurrentPrincipal() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!AuthenticationService.isAuthenticated(auth)) {
            return Optional.empty();
        }
        return Optional.of(InternalPrincipal.from(auth));
    }

    public String getCurrentUsername() {
        return getCurrentPrincipal().map(InternalPrincipal::username).orElse("");
    }
}

