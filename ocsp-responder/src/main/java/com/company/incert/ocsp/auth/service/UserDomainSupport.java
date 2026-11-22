package com.company.incert.ocsp.auth.service;

import com.company.incert.ocsp.auth.config.AdminUserInitializer;
import com.company.incert.ocsp.auth.dto.RoleDto;
import com.company.incert.ocsp.auth.dto.UserDto;
import com.company.incert.ocsp.auth.entity.RoleEntity;
import com.company.incert.ocsp.auth.entity.UserEntity;
import com.company.incert.ocsp.auth.repository.RoleRepository;
import com.company.incert.ocsp.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Shared user/role validation, admin-invariant guards, GDPR anonymization, and DTO mapping
 * used across {@link LocalIdentityService}, {@link KeycloakIdentityService}, and {@link KeycloakSyncService}.
 */
@Component
@RequiredArgsConstructor
public class UserDomainSupport {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public List<UserDto> listActiveUsers() {
        return userRepository.findAllByDeletedAtIsNull().stream()
                .sorted(Comparator.comparing(UserEntity::getCreatedAt, Comparator.nullsLast(Comparator.naturalOrder())))
                .map(this::toDto)
                .toList();
    }

    public List<RoleDto> listRoles() {
        return roleRepository.findAll().stream()
                .sorted(Comparator.comparing(RoleEntity::getName))
                .map(r -> new RoleDto(r.getId(), r.getName(), r.getDescription()))
                .toList();
    }

    public UserEntity findActiveById(String userId) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + userId));
        if (user.isDeleted()) {
            throw new IllegalArgumentException("User has been deleted: " + userId);
        }
        return user;
    }

    public Set<RoleEntity> resolveRoles(List<String> roleNames) {
        Set<RoleEntity> result = new HashSet<>();
        if (roleNames != null) {
            for (String raw : roleNames) {
                if (raw == null || raw.isBlank()) continue;
                String normalized = raw.trim().toUpperCase();
                if (!normalized.startsWith("ROLE_")) {
                    normalized = "ROLE_" + normalized;
                }
                String finalName = normalized;
                RoleEntity role = roleRepository.findByName(finalName)
                        .orElseThrow(() -> new IllegalArgumentException("Unknown role: " + finalName));
                result.add(role);
            }
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("At least one valid role must be specified");
        }
        return result;
    }

    public void assertCanMutateAdminStatus(UserEntity target, boolean willBeAdmin, boolean willBeEnabled, String actingUsername) {
        boolean currentlyActiveAdmin = hasAdminRole(target) && target.isEnabled();
        if (currentlyActiveAdmin && (!willBeAdmin || !willBeEnabled) && countEnabledAdmins() <= 1) {
            throw new IllegalStateException("Cannot disable or demote the last remaining active administrator");
        }
        if (!willBeEnabled && actingUsername != null && target.getUsername().equalsIgnoreCase(actingUsername)) {
            throw new IllegalStateException("You cannot disable your own active account");
        }
    }

    public void assertCanDelete(UserEntity target, String actingUsername) {
        if (actingUsername != null && target.getUsername().equalsIgnoreCase(actingUsername)) {
            throw new IllegalStateException("You cannot delete your own account");
        }
        if (hasAdminRole(target) && target.isEnabled() && countEnabledAdmins() <= 1) {
            throw new IllegalStateException("Cannot delete the last remaining active administrator");
        }
    }

    public void softDeleteOrAnonymize(UserEntity user, boolean anonymizeGdpr) {
        user.setEnabled(false);
        user.setDeletedAt(Instant.now());
        user.setPasswordHash(null);
        if (anonymizeGdpr) {
            user.setUsername("deleted-" + user.getId());
            user.setEmail(null);
            user.setEmailVerified(false);
            user.setFullName("Anonymized User");
            user.setPreferencesJson(null);
            user.setExternalId(null);
        }
        userRepository.save(user);
    }

    public boolean hasAdminRole(UserEntity user) {
        return user.getRoles().stream().anyMatch(r -> AdminUserInitializer.ROLE_ADMIN.equals(r.getName()));
    }

    public long countEnabledAdmins() {
        return userRepository.findAllByDeletedAtIsNull().stream()
                .filter(UserEntity::isEnabled)
                .filter(this::hasAdminRole)
                .count();
    }

    public UserDto toDto(UserEntity user) {
        List<String> roleNames = user.getRoles().stream()
                .map(RoleEntity::getName)
                .sorted()
                .toList();
        return new UserDto(
                user.getId(),
                user.getExternalId(),
                user.getAuthSource(),
                user.getUsername(),
                user.getEmail(),
                user.isEmailVerified(),
                user.getFullName(),
                user.isEnabled(),
                user.getTenantId(),
                roleNames,
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }
}

