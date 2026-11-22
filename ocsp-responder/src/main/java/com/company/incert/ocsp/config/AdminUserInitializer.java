package com.company.incert.ocsp.config;

import com.company.incert.ocsp.entity.AuthSource;
import com.company.incert.ocsp.entity.RoleEntity;
import com.company.incert.ocsp.entity.UserEntity;
import com.company.incert.ocsp.repository.RoleRepository;
import com.company.incert.ocsp.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Initializes default RBAC roles ({@code ROLE_ADMIN}, {@code ROLE_AGENT}, {@code ROLE_AUDITOR})
 * and seeds the built-in administrator account from {@link AdminProperties} into {@code ocsp.users}
 * on startup if not yet present.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AdminUserInitializer {

    public static final String ROLE_ADMIN = "ROLE_ADMIN";
    public static final String ROLE_AGENT = "ROLE_AGENT";
    public static final String ROLE_AUDITOR = "ROLE_AUDITOR";

    private static final Map<String, String> DEFAULT_ROLES = Map.of(
        ROLE_ADMIN, "Full administrative access: user management, signing certificate activation/deactivation/deletion, CSR generation, and audit",
        ROLE_AGENT, "Operational agent access: generate HSM CSRs, import signing certificates, trigger renewal CSRs and reconciliation",
        ROLE_AUDITOR, "Read-only audit access: dashboard metrics, revocation feed, inbox audit, validity reports, and certificate checker"
    );

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AdminProperties adminProperties;

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void initializeBuiltInAdmin() {
        DEFAULT_ROLES.forEach((roleName, description) ->
            roleRepository.findByName(roleName).orElseGet(() ->
                roleRepository.save(RoleEntity.builder()
                    .name(roleName)
                    .description(description)
                    .build())
            )
        );

        String username = adminProperties.getUsername();
        String rawPassword = adminProperties.getPassword();
        if (username == null || username.isBlank() || rawPassword == null || rawPassword.isBlank()) {
            log.warn("Built-in admin properties (admin.username / admin.password) are empty; skipping admin initialization");
            return;
        }

        String normalizedUsername = username.trim();
        RoleEntity adminRole = roleRepository.findByName(ROLE_ADMIN)
                .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN was not initialized"));

        userRepository.findByUsername(normalizedUsername).ifPresentOrElse(
            existing -> log.debug("Built-in admin user '{}' already exists in users table", normalizedUsername),
            () -> {
                UserEntity adminUser = UserEntity.builder()
                        .id(UUID.randomUUID().toString())
                        .authSource(AuthSource.LOCAL)
                        .username(normalizedUsername)
                        .email(normalizedUsername + "@incert.local")
                        .emailVerified(true)
                        .fullName("Incert Administrator")
                        .passwordHash(passwordEncoder.encode(rawPassword))
                        .enabled(true)
                        .tenantId("default")
                        .roles(Set.of(adminRole))
                        .build();
                userRepository.save(adminUser);
                log.info("Initialized built-in admin user '{}' (uuid={}) with role {}",
                        normalizedUsername, adminUser.getId(), ROLE_ADMIN);
            }
        );
    }
}
