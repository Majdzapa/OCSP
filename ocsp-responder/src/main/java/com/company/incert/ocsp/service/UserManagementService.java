package com.company.incert.ocsp.service;

import com.company.incert.ocsp.config.AdminUserInitializer;
import com.company.incert.ocsp.dto.CreateUserRequest;
import com.company.incert.ocsp.dto.RoleDto;
import com.company.incert.ocsp.dto.UpdateUserRequest;
import com.company.incert.ocsp.dto.UserDto;
import com.company.incert.ocsp.entity.RoleEntity;
import com.company.incert.ocsp.entity.UserEntity;
import com.company.incert.ocsp.repository.RoleRepository;
import com.company.incert.ocsp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Admin-only user and role management service backed by {@code users} and {@code roles}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserManagementService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional(readOnly = true)
    public List<UserDto> listUsers() {
        return userRepository.findAll().stream()
                .sorted(Comparator.comparing(UserEntity::getId))
                .map(this::toDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<RoleDto> listRoles() {
        return roleRepository.findAll().stream()
                .sorted(Comparator.comparing(RoleEntity::getName))
                .map(r -> new RoleDto(r.getId(), r.getName(), r.getDescription()))
                .toList();
    }

    @Transactional
    public UserDto createUser(CreateUserRequest request) {
        String username = request.username().trim();
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("User '" + username + "' already exists");
        }
        Set<RoleEntity> resolvedRoles = resolveRoles(request.roles());
        UserEntity user = UserEntity.builder()
                .username(username)
                .passwordHash(passwordEncoder.encode(request.password()))
                .enabled(request.enabled() == null || request.enabled())
                .roles(resolvedRoles)
                .build();
        UserEntity saved = userRepository.save(user);
        log.info("Created user '{}' with roles {}", saved.getUsername(), saved.getRoles().stream().map(RoleEntity::getName).toList());
        return toDto(saved);
    }

    @Transactional
    public UserDto updateUser(Long id, UpdateUserRequest request, String actingUsername) {
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));

        if (request.roles() != null && !request.roles().isEmpty()) {
            Set<RoleEntity> newRoles = resolveRoles(request.roles());
            boolean removingAdmin = hasAdminRole(user) && newRoles.stream().noneMatch(r -> AdminUserInitializer.ROLE_ADMIN.equals(r.getName()));
            if (removingAdmin && countEnabledAdmins() <= 1) {
                throw new IllegalStateException("Cannot remove ROLE_ADMIN from the last remaining active administrator");
            }
            user.setRoles(newRoles);
        }

        if (request.enabled() != null) {
            if (!request.enabled() && hasAdminRole(user) && user.isEnabled() && countEnabledAdmins() <= 1) {
                throw new IllegalStateException("Cannot disable the last remaining active administrator");
            }
            if (!request.enabled() && user.getUsername().equalsIgnoreCase(actingUsername)) {
                throw new IllegalStateException("You cannot disable your own active account");
            }
            user.setEnabled(request.enabled());
        }

        if (request.password() != null && !request.password().isBlank()) {
            user.setPasswordHash(passwordEncoder.encode(request.password()));
        }

        UserEntity saved = userRepository.save(user);
        log.info("Updated user '{}' (enabled={}, roles={})",
                saved.getUsername(), saved.isEnabled(), saved.getRoles().stream().map(RoleEntity::getName).toList());
        return toDto(saved);
    }

    @Transactional
    public void deleteUser(Long id, String actingUsername) {
        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + id));

        if (user.getUsername().equalsIgnoreCase(actingUsername)) {
            throw new IllegalStateException("You cannot delete your own account");
        }
        if (hasAdminRole(user) && user.isEnabled() && countEnabledAdmins() <= 1) {
            throw new IllegalStateException("Cannot delete the last remaining active administrator");
        }

        userRepository.delete(user);
        log.info("Deleted user '{}' (id={})", user.getUsername(), id);
    }

    private Set<RoleEntity> resolveRoles(List<String> roleNames) {
        Set<RoleEntity> result = new HashSet<>();
        for (String raw : roleNames) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            String normalized = raw.trim().toUpperCase();
            if (!normalized.startsWith("ROLE_")) {
                normalized = "ROLE_" + normalized;
            }
            String finalName = normalized;
            RoleEntity role = roleRepository.findByName(finalName)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown role: " + finalName));
            result.add(role);
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("At least one valid role must be specified");
        }
        return result;
    }

    private boolean hasAdminRole(UserEntity user) {
        return user.getRoles().stream().anyMatch(r -> AdminUserInitializer.ROLE_ADMIN.equals(r.getName()));
    }

    private long countEnabledAdmins() {
        return userRepository.findAll().stream()
                .filter(UserEntity::isEnabled)
                .filter(this::hasAdminRole)
                .count();
    }

    private UserDto toDto(UserEntity user) {
        List<String> roleNames = user.getRoles().stream()
                .map(RoleEntity::getName)
                .sorted()
                .toList();
        return new UserDto(user.getId(), user.getUsername(), user.isEnabled(), roleNames, user.getCreatedAt(), user.getUpdatedAt());
    }
}

