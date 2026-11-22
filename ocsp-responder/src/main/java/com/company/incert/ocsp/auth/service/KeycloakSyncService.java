package com.company.incert.ocsp.auth.service;

import com.company.incert.ocsp.auth.config.AppAuthProperties;
import com.company.incert.ocsp.auth.entity.AuthSource;
import com.company.incert.ocsp.auth.entity.RoleEntity;
import com.company.incert.ocsp.auth.entity.UserEntity;
import com.company.incert.ocsp.auth.repository.RoleRepository;
import com.company.incert.ocsp.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

/**
 * Authoritative synchronizer for the local read-only identity replica in {@code KEYCLOAK} mode.
 * <p>
 * All handlers are idempotent upserts keyed by {@code external_id} (Keycloak {@code sub}):
 * <ul>
 *   <li>JIT provisioning on login (creates missing replica, refreshes email/name/enabled from JWT claims)</li>
 *   <li>Event listener (webhook) for CREATE, UPDATE, DELETE, DISABLE</li>
 *   <li>Nightly reconciliation job via {@link KeycloakAdminClient}</li>
 * </ul>
 * Never stores passwords or tokens for Keycloak users. Links an existing LOCAL account only when
 * {@code emailVerified == true} and the verified email matches.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KeycloakSyncService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final KeycloakAdminClient keycloakAdminClient;
    private final AppAuthProperties authProperties;

    /**
     * JIT provisioning on login: idempotent upsert keyed by {@code external_id} ({@code sub}).
     */
    @Transactional
    public UserEntity upsertFromTokenClaims(
            String externalId,
            String username,
            String email,
            boolean emailVerified,
            String fullName,
            Collection<String> tokenRoles) {
        if (externalId == null || externalId.isBlank()) {
            throw new IllegalArgumentException("Keycloak token subject (sub) is required");
        }

        Optional<UserEntity> bySub = userRepository.findByExternalId(externalId);
        UserEntity user = bySub.orElse(null);

        // Link existing LOCAL account ONLY on verified-email match
        if (user == null && emailVerified && email != null && !email.isBlank()) {
            user = userRepository.findByEmailIgnoreCaseAndEmailVerifiedTrueAndDeletedAtIsNull(email.trim())
                    .orElse(null);
            if (user != null) {
                log.info("Linking existing user id={} to Keycloak external_id={} via verified email", user.getId(), externalId);
            }
        }

        if (user == null && username != null && !username.isBlank()) {
            // If an existing unlinked local bootstrap record shares the username (e.g. initial 'admin' seed),
            // bind it ONLY when its auth_source is KEYCLOAK or email is verified.
            user = userRepository.findByUsername(username.trim())
                    .filter(existing -> existing.getExternalId() == null && existing.isEmailVerified() && emailVerified
                            && email != null && email.equalsIgnoreCase(existing.getEmail()))
                    .orElse(null);
        }

        if (user == null) {
            Set<RoleEntity> resolvedRoles = resolveCoarseRoles(tokenRoles);
            user = UserEntity.builder()
                    .id(UUID.randomUUID().toString())
                    .externalId(externalId)
                    .authSource(AuthSource.KEYCLOAK)
                    .username(resolveUniqueUsername(username, externalId))
                    .email(email)
                    .emailVerified(emailVerified)
                    .fullName(fullName)
                    .enabled(true)
                    .passwordHash(null)
                    .tenantId("default")
                    .roles(resolvedRoles)
                    .build();
        } else {
            user.setExternalId(externalId);
            user.setAuthSource(AuthSource.KEYCLOAK);
            if (username != null && !username.isBlank()) {
                user.setUsername(username.trim());
            }
            user.setEmail(email);
            user.setEmailVerified(emailVerified);
            user.setFullName(fullName);
            user.setPasswordHash(null); // Never store passwords for Keycloak users
            user.setDeletedAt(null);
            if (user.getRoles() == null || user.getRoles().isEmpty()) {
                user.setRoles(resolveCoarseRoles(tokenRoles));
            }
        }

        return userRepository.save(user);
    }

    /**
     * Handles webhook events from Keycloak (CREATE, UPDATE, DELETE, DISABLE) idempotently by {@code external_id}.
     */
    @Transactional
    public void handleWebhookEvent(
            String eventType,
            String externalId,
            String username,
            String email,
            Boolean emailVerified,
            String fullName,
            Boolean enabled) {
        if (externalId == null || externalId.isBlank()) {
            return;
        }
        String normalizedType = eventType != null ? eventType.trim().toUpperCase() : "UPDATE";

        switch (normalizedType) {
            case "DELETE" -> userRepository.findByExternalId(externalId).ifPresent(user -> {
                user.setEnabled(false);
                user.setDeletedAt(Instant.now());
                user.setPasswordHash(null);
                userRepository.save(user);
                log.info("[KEYCLOAK-WEBHOOK] Soft-deleted user external_id={}", externalId);
            });
            case "DISABLE" -> userRepository.findByExternalId(externalId).ifPresent(user -> {
                user.setEnabled(false);
                userRepository.save(user);
                log.info("[KEYCLOAK-WEBHOOK] Disabled user external_id={}", externalId);
            });
            default -> {
                UserEntity user = userRepository.findByExternalId(externalId)
                        .orElseGet(() -> UserEntity.builder()
                                .id(UUID.randomUUID().toString())
                                .externalId(externalId)
                                .authSource(AuthSource.KEYCLOAK)
                                .username(resolveUniqueUsername(username, externalId))
                                .roles(resolveCoarseRoles(List.of("ROLE_AUDITOR")))
                                .build());
                if (username != null && !username.isBlank()) user.setUsername(username.trim());
                if (email != null) user.setEmail(email.isBlank() ? null : email.trim());
                if (emailVerified != null) user.setEmailVerified(emailVerified);
                if (fullName != null) user.setFullName(fullName.isBlank() ? null : fullName.trim());
                if (enabled != null) user.setEnabled(enabled);
                user.setAuthSource(AuthSource.KEYCLOAK);
                user.setPasswordHash(null);
                user.setDeletedAt(null);
                userRepository.save(user);
                log.info("[KEYCLOAK-WEBHOOK] Upserted user external_id={} event={}", externalId, normalizedType);
            }
        }
    }

    /**
     * Nightly reconciliation job: fetches authoritative user list from Keycloak Admin API
     * and idempotently reconciles the local {@code KEYCLOAK} replica.
     */
    @Transactional
    public int reconcileAllFromKeycloak() {
        if (!authProperties.resolvedMode().isKeycloak()) {
            return 0;
        }
        List<KeycloakAdminClient.KeycloakUserRepresentation> remoteUsers = keycloakAdminClient.listAllUsers();
        Set<String> activeRemoteSubs = new HashSet<>();

        for (var remote : remoteUsers) {
            if (remote.id() == null) continue;
            activeRemoteSubs.add(remote.id());

            UserEntity local = userRepository.findByExternalId(remote.id()).orElse(null);
            if (local == null) {
                local = UserEntity.builder()
                        .id(UUID.randomUUID().toString())
                        .externalId(remote.id())
                        .authSource(AuthSource.KEYCLOAK)
                        .username(resolveUniqueUsername(remote.username(), remote.id()))
                        .email(remote.email())
                        .emailVerified(remote.emailVerified())
                        .fullName(remote.fullName())
                        .enabled(remote.enabled())
                        .passwordHash(null)
                        .tenantId("default")
                        .roles(resolveCoarseRoles(List.of("ROLE_AUDITOR")))
                        .build();
            } else {
                local.setUsername(remote.username());
                local.setEmail(remote.email());
                local.setEmailVerified(remote.emailVerified());
                local.setFullName(remote.fullName());
                local.setEnabled(remote.enabled());
                local.setPasswordHash(null);
                local.setDeletedAt(null);
            }
            userRepository.save(local);
        }

        // Soft-delete local KEYCLOAK replicas that no longer exist in Keycloak
        for (UserEntity localKc : userRepository.findAllByAuthSourceAndDeletedAtIsNull(AuthSource.KEYCLOAK)) {
            if (localKc.getExternalId() != null && !activeRemoteSubs.contains(localKc.getExternalId())) {
                localKc.setEnabled(false);
                localKc.setDeletedAt(Instant.now());
                userRepository.save(localKc);
            }
        }

        log.info("[KEYCLOAK-RECONCILE] Reconciled {} users from Keycloak Admin API", remoteUsers.size());
        return remoteUsers.size();
    }

    private Set<RoleEntity> resolveCoarseRoles(Collection<String> tokenRoles) {
        Set<RoleEntity> resolved = new HashSet<>();
        if (tokenRoles != null) {
            for (String roleName : tokenRoles) {
                roleRepository.findByName(roleName).ifPresent(resolved::add);
            }
        }
        if (resolved.isEmpty()) {
            roleRepository.findByName("ROLE_AUDITOR").ifPresent(resolved::add);
        }
        return resolved;
    }

    private String resolveUniqueUsername(String preferred, String externalId) {
        String base = (preferred != null && !preferred.isBlank()) ? preferred.trim() : "kc-" + externalId;
        if (!userRepository.existsByUsernameAndDeletedAtIsNull(base)) {
            return base;
        }
        return base + "-" + externalId.substring(0, Math.min(8, externalId.length()));
    }
}

