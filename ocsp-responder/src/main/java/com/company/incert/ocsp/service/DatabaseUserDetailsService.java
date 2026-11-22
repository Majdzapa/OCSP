package com.company.incert.ocsp.service;

import com.company.incert.ocsp.entity.RoleEntity;
import com.company.incert.ocsp.entity.UserEntity;
import com.company.incert.ocsp.repository.UserRepository;
import com.company.incert.ocsp.security.InternalPrincipal;
import com.company.incert.ocsp.security.InternalUserDetails;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Loads active users from {@code ocsp.users} and wraps them in {@link InternalUserDetails}
 * so both {@code SELF_MANAGEMENT} and {@code KEYCLOAK} modes produce the exact same {@link InternalPrincipal}.
 */
@Service
@RequiredArgsConstructor
public class DatabaseUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username == null || username.isBlank()) {
            throw new UsernameNotFoundException("Username is required");
        }
        UserEntity user = userRepository.findByUsernameAndDeletedAtIsNull(username.trim())
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        if (user.getPasswordHash() == null) {
            throw new UsernameNotFoundException("User '" + username + "' has no local credentials");
        }

        Set<String> roles = user.getRoles().stream()
                .map(RoleEntity::getName)
                .collect(Collectors.toSet());

        InternalPrincipal principal = new InternalPrincipal(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getFullName(),
                user.getTenantId(),
                user.getAuthSource(),
                roles
        );
        return new InternalUserDetails(principal, user.getPasswordHash(), user.isEnabled());
    }
}
