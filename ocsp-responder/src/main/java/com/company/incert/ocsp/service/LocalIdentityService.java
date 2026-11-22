package com.company.incert.ocsp.service;

import com.company.incert.ocsp.config.OnSelfManagementModeCondition;
import com.company.incert.ocsp.dto.CreateUserRequest;
import com.company.incert.ocsp.dto.RoleDto;
import com.company.incert.ocsp.dto.UpdateUserRequest;
import com.company.incert.ocsp.dto.UserDto;
import com.company.incert.ocsp.entity.AuthSource;
import com.company.incert.ocsp.entity.RoleEntity;
import com.company.incert.ocsp.entity.UserEntity;
import com.company.incert.ocsp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * {@link IdentityService} implementation for {@code app.auth.mode=SELF_MANAGEMENT}.
 * Owns credentials, identity, and app profile in the application database.
 */
@Slf4j
@Service
@Conditional(OnSelfManagementModeCondition.class)
@RequiredArgsConstructor
public class LocalIdentityService implements IdentityService {

    private final UserRepository userRepository;
    private final UserDomainSupport support;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional(readOnly = true)
    public List<UserDto> listUsers() {
        return support.listActiveUsers();
    }

    @Override
    @Transactional(readOnly = true)
    public List<RoleDto> listRoles() {
        return support.listRoles();
    }

    @Override
    @Transactional
    public UserDto createUser(CreateUserRequest request) {
        String username = request.username().trim();
        if (userRepository.existsByUsernameAndDeletedAtIsNull(username)) {
            throw new IllegalArgumentException("User '" + username + "' already exists");
        }
        if (request.password() == null || request.password().isBlank()) {
            throw new IllegalArgumentException("Password is required in SELF_MANAGEMENT mode");
        }
        Set<RoleEntity> roles = support.resolveRoles(request.roles());

        UserEntity user = UserEntity.builder()
                .id(UUID.randomUUID().toString())
                .authSource(AuthSource.LOCAL)
                .username(username)
                .email(request.email() != null && !request.email().isBlank() ? request.email().trim() : null)
                .emailVerified(false)
                .fullName(request.fullName() != null && !request.fullName().isBlank() ? request.fullName().trim() : null)
                .passwordHash(passwordEncoder.encode(request.password()))
                .enabled(request.enabled() == null || request.enabled())
                .tenantId(request.tenantId() != null && !request.tenantId().isBlank() ? request.tenantId().trim() : "default")
                .roles(roles)
                .build();

        UserEntity saved = userRepository.save(user);
        log.info("[SELF_MANAGEMENT] Created LOCAL user id={} username='{}' roles={}",
                saved.getId(), saved.getUsername(), saved.getRoles().stream().map(RoleEntity::getName).toList());
        return support.toDto(saved);
    }

    @Override
    @Transactional
    public UserDto updateUser(String userId, UpdateUserRequest request, String actingUsername) {
        UserEntity user = support.findActiveById(userId);

        Set<RoleEntity> newRoles = (request.roles() != null && !request.roles().isEmpty())
                ? support.resolveRoles(request.roles())
                : user.getRoles();
        boolean willBeAdmin = newRoles.stream().anyMatch(r -> "ROLE_ADMIN".equals(r.getName()));
        boolean willBeEnabled = request.enabled() != null ? request.enabled() : user.isEnabled();

        support.assertCanMutateAdminStatus(user, willBeAdmin, willBeEnabled, actingUsername);

        user.setRoles(newRoles);
        user.setEnabled(willBeEnabled);
        if (request.email() != null) {
            user.setEmail(request.email().isBlank() ? null : request.email().trim());
        }
        if (request.fullName() != null) {
            user.setFullName(request.fullName().isBlank() ? null : request.fullName().trim());
        }
        if (request.tenantId() != null && !request.tenantId().isBlank()) {
            user.setTenantId(request.tenantId().trim());
        }
        if (request.password() != null && !request.password().isBlank()) {
            user.setPasswordHash(passwordEncoder.encode(request.password()));
        }

        UserEntity saved = userRepository.save(user);
        log.info("[SELF_MANAGEMENT] Updated LOCAL user id={} username='{}'", saved.getId(), saved.getUsername());
        return support.toDto(saved);
    }

    @Override
    @Transactional
    public UserDto setEnabled(String userId, boolean enabled, String actingUsername) {
        UserEntity user = support.findActiveById(userId);
        support.assertCanMutateAdminStatus(user, support.hasAdminRole(user), enabled, actingUsername);
        user.setEnabled(enabled);
        return support.toDto(userRepository.save(user));
    }

    @Override
    @Transactional
    public void resetPassword(String userId, String newPassword) {
        if (newPassword == null || newPassword.isBlank()) {
            throw new IllegalArgumentException("New password is required");
        }
        if (newPassword.length() < 4 || newPassword.length() > 128) {
            throw new IllegalArgumentException("New password must be between 4 and 128 characters");
        }
        UserEntity user = support.findActiveById(userId);
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        log.info("[SELF_MANAGEMENT] Password reset for user id={} username='{}'", user.getId(), user.getUsername());
    }

    @Override
    @Transactional
    public void deleteUser(String userId, boolean anonymizeGdpr, String actingUsername) {
        UserEntity user = support.findActiveById(userId);
        support.assertCanDelete(user, actingUsername);
        support.softDeleteOrAnonymize(user, anonymizeGdpr);
        log.info("[SELF_MANAGEMENT] Soft-deleted user id={} (anonymized={})", userId, anonymizeGdpr);
    }
}

