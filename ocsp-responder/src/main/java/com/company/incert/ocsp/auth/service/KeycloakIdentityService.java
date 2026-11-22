package com.company.incert.ocsp.auth.service;

import com.company.incert.ocsp.auth.config.OnKeycloakModeCondition;
import com.company.incert.ocsp.auth.dto.CreateUserRequest;
import com.company.incert.ocsp.auth.dto.RoleDto;
import com.company.incert.ocsp.auth.dto.UpdateUserRequest;
import com.company.incert.ocsp.auth.dto.UserDto;
import com.company.incert.ocsp.auth.entity.AuthSource;
import com.company.incert.ocsp.auth.entity.RoleEntity;
import com.company.incert.ocsp.auth.entity.UserEntity;
import com.company.incert.ocsp.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Conditional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * {@link IdentityService} implementation for {@code app.auth.mode=KEYCLOAK}.
 * <p>
 * Keycloak owns credentials and identity. Operations call the Keycloak Admin REST API first,
 * then upsert the local read-only identity replica keyed by {@code external_id} ({@code sub}).
 * Passwords are never stored locally for Keycloak users.
 */
@Slf4j
@Service
@Conditional(OnKeycloakModeCondition.class)
@RequiredArgsConstructor
public class KeycloakIdentityService implements IdentityService {

    private final UserRepository userRepository;
    private final UserDomainSupport support;
    private final KeycloakAdminClient keycloakAdminClient;
    private final IdentityOutboxService outboxService;

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
        if (request.password() != null && !request.password().isBlank()) {
            throw new IllegalArgumentException("Passwords are owned by Keycloak in KEYCLOAK mode and must not be submitted");
        }
        String username = request.username().trim();
        if (userRepository.existsByUsernameAndDeletedAtIsNull(username)) {
            throw new IllegalArgumentException("User '" + username + "' already exists");
        }
        Set<RoleEntity> roles = support.resolveRoles(request.roles());
        boolean enabled = request.enabled() == null || request.enabled();

        // 1. Call Keycloak Admin API first (source of truth for identity)
        String externalId = keycloakAdminClient.createUser(username, request.email(), request.fullName(), enabled);

        // 2. Upsert local DB replica keyed by external_id (no password_hash)
        UserEntity replica = userRepository.findByExternalId(externalId)
                .orElseGet(() -> UserEntity.builder()
                        .id(UUID.randomUUID().toString())
                        .externalId(externalId)
                        .build());

        replica.setAuthSource(AuthSource.KEYCLOAK);
        replica.setUsername(username);
        replica.setEmail(request.email() != null && !request.email().isBlank() ? request.email().trim() : null);
        replica.setFullName(request.fullName() != null && !request.fullName().isBlank() ? request.fullName().trim() : null);
        replica.setEnabled(enabled);
        replica.setPasswordHash(null);
        replica.setDeletedAt(null);
        replica.setTenantId(request.tenantId() != null && !request.tenantId().isBlank() ? request.tenantId().trim() : "default");
        replica.setRoles(roles);

        UserEntity saved = userRepository.save(replica);
        log.info("[KEYCLOAK] Created user in Keycloak (external_id={}) and upserted DB replica id={}", externalId, saved.getId());
        return support.toDto(saved);
    }

    @Override
    @Transactional
    public UserDto updateUser(String userId, UpdateUserRequest request, String actingUsername) {
        if (request.password() != null && !request.password().isBlank()) {
            throw new IllegalArgumentException("Passwords are owned by Keycloak in KEYCLOAK mode");
        }
        UserEntity user = support.findActiveById(userId);
        Set<RoleEntity> newRoles = (request.roles() != null && !request.roles().isEmpty())
                ? support.resolveRoles(request.roles())
                : user.getRoles();
        boolean willBeAdmin = newRoles.stream().anyMatch(r -> "ROLE_ADMIN".equals(r.getName()));
        boolean willBeEnabled = request.enabled() != null ? request.enabled() : user.isEnabled();

        support.assertCanMutateAdminStatus(user, willBeAdmin, willBeEnabled, actingUsername);

        // Identity changes go to Keycloak first if user has an externalId
        if (user.getExternalId() != null) {
            try {
                keycloakAdminClient.updateUser(user.getExternalId(), request.email(), request.fullName(), request.enabled());
            } catch (Exception e) {
                Map<String, Object> payload = new LinkedHashMap<>();
                payload.put("externalId", user.getExternalId());
                if (request.email() != null) payload.put("email", request.email());
                if (request.fullName() != null) payload.put("fullName", request.fullName());
                if (request.enabled() != null) payload.put("enabled", request.enabled());
                outboxService.recordPending(user.getId(), "UPDATE", payload, e.getMessage());
            }
        }

        // Update app-owned fields (roles, tenantId) and sync replica fields
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
        user.setPasswordHash(null);

        return support.toDto(userRepository.save(user));
    }

    @Override
    @Transactional
    public UserDto setEnabled(String userId, boolean enabled, String actingUsername) {
        UserEntity user = support.findActiveById(userId);
        support.assertCanMutateAdminStatus(user, support.hasAdminRole(user), enabled, actingUsername);

        if (user.getExternalId() != null) {
            try {
                keycloakAdminClient.updateUser(user.getExternalId(), null, null, enabled);
            } catch (Exception e) {
                outboxService.recordPending(user.getId(), "SET_ENABLED",
                        Map.of("externalId", user.getExternalId(), "enabled", enabled), e.getMessage());
            }
        }
        user.setEnabled(enabled);
        return support.toDto(userRepository.save(user));
    }

    @Override
    @Transactional
    public void resetPassword(String userId, String newPassword) {
        UserEntity user = support.findActiveById(userId);
        if (user.getExternalId() == null) {
            throw new IllegalStateException("User has no Keycloak external_id; cannot trigger password reset email");
        }
        try {
            keycloakAdminClient.sendResetPasswordEmail(user.getExternalId());
        } catch (Exception e) {
            outboxService.recordPending(user.getId(), "RESET_PASSWORD",
                    Map.of("externalId", user.getExternalId()), e.getMessage());
            throw new IllegalStateException("Queued password reset action for retry: " + e.getMessage(), e);
        }
    }

    @Override
    @Transactional
    public void deleteUser(String userId, boolean anonymizeGdpr, String actingUsername) {
        UserEntity user = support.findActiveById(userId);
        support.assertCanDelete(user, actingUsername);

        if (user.getExternalId() != null) {
            try {
                keycloakAdminClient.deleteUser(user.getExternalId());
            } catch (Exception e) {
                outboxService.recordPending(user.getId(), "DELETE",
                        Map.of("externalId", user.getExternalId()), e.getMessage());
            }
        }
        support.softDeleteOrAnonymize(user, anonymizeGdpr);
        log.info("[KEYCLOAK] Soft-deleted user replica id={} (anonymized={})", userId, anonymizeGdpr);
    }
}

