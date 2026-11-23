package com.company.incert.ocsp.auth.security;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.Serializable;

/**
 * Evaluates {@code @PreAuthorize("hasPermission(null, '<PERMISSION>')")} expressions
 * against {@link SecurityPermissions} derived from the authenticated principal's roles.
 */
@Component
public class OcspPermissionEvaluator implements PermissionEvaluator {

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || !authentication.isAuthenticated() || permission == null) {
            return false;
        }
        SecurityPermissions required = parsePermission(permission);
        if (required == null) {
            return false;
        }
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if (SecurityPermissions.forRole(authority.getAuthority()).contains(required)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return hasPermission(authentication, targetType, permission);
    }

    private static SecurityPermissions parsePermission(Object permission) {
        if (permission instanceof SecurityPermissions sp) {
            return sp;
        }
        try {
            return SecurityPermissions.valueOf(permission.toString().trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

