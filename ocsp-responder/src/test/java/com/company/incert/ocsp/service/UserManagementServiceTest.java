package com.company.incert.ocsp.service;

import com.company.incert.ocsp.config.AdminProperties;
import com.company.incert.ocsp.config.AdminUserInitializer;
import com.company.incert.ocsp.config.AppAuthProperties;
import com.company.incert.ocsp.dto.CreateUserRequest;
import com.company.incert.ocsp.dto.UserDto;
import com.company.incert.ocsp.entity.AuthSource;
import com.company.incert.ocsp.entity.RoleEntity;
import com.company.incert.ocsp.entity.UserEntity;
import com.company.incert.ocsp.repository.RoleRepository;
import com.company.incert.ocsp.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserManagementServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private KeycloakAdminClient keycloakAdminClient;

    @Mock
    private IdentityOutboxService outboxService;

    private PasswordEncoder passwordEncoder;
    private UserDomainSupport support;
    private LocalIdentityService localIdentityService;
    private KeycloakIdentityService keycloakIdentityService;
    private KeycloakSyncService keycloakSyncService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        support = new UserDomainSupport(userRepository, roleRepository);
        localIdentityService = new LocalIdentityService(userRepository, support, passwordEncoder);
        keycloakIdentityService = new KeycloakIdentityService(userRepository, support, keycloakAdminClient, outboxService);

        AppAuthProperties authProperties = new AppAuthProperties();
        authProperties.setMode("KEYCLOAK");
        keycloakSyncService = new KeycloakSyncService(userRepository, roleRepository, keycloakAdminClient, authProperties);
    }

    @Test
    void initializer_createsBuiltInAdminWithUuidAndLocalSource() {
        AdminProperties props = new AdminProperties();
        props.setUsername("admin");
        props.setPassword("secret123");

        RoleEntity adminRole = RoleEntity.builder().id(1L).name("ROLE_ADMIN").build();
        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.of(adminRole));
        when(roleRepository.findByName("ROLE_AGENT")).thenReturn(Optional.of(RoleEntity.builder().id(2L).name("ROLE_AGENT").build()));
        when(roleRepository.findByName("ROLE_AUDITOR")).thenReturn(Optional.of(RoleEntity.builder().id(3L).name("ROLE_AUDITOR").build()));
        when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        AppAuthProperties authProps = new AppAuthProperties();
        authProps.setMode("SELF_MANAGEMENT");
        AdminUserInitializer initializer = new AdminUserInitializer(userRepository, roleRepository, passwordEncoder, props, authProps);
        initializer.initializeBuiltInAdmin();

        ArgumentCaptor<UserEntity> captor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository).save(captor.capture());
        UserEntity saved = captor.getValue();
        assertThat(saved.getId()).isNotBlank();
        assertThat(saved.getAuthSource()).isEqualTo(AuthSource.LOCAL);
        assertThat(saved.getUsername()).isEqualTo("admin");
        assertThat(passwordEncoder.matches("secret123", saved.getPasswordHash())).isTrue();
        assertThat(saved.getRoles()).extracting(RoleEntity::getName).containsExactly("ROLE_ADMIN");
    }

    @Test
    void localMode_createUser_hashesPasswordAndAssignsLocalSource() {
        RoleEntity agentRole = RoleEntity.builder().id(2L).name("ROLE_AGENT").build();
        when(userRepository.existsByUsernameAndDeletedAtIsNull("agent1")).thenReturn(false);
        when(roleRepository.findByName("ROLE_AGENT")).thenReturn(Optional.of(agentRole));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserDto dto = localIdentityService.createUser(new CreateUserRequest(
                "agent1", "agent1@incert.local", "Agent One", "pass123", true, "tenant-a", List.of("AGENT")));

        assertThat(dto.id()).isNotBlank();
        assertThat(dto.authSource()).isEqualTo(AuthSource.LOCAL);
        assertThat(dto.username()).isEqualTo("agent1");
        assertThat(dto.tenantId()).isEqualTo("tenant-a");
        assertThat(dto.roles()).containsExactly("ROLE_AGENT");
    }

    @Test
    void keycloakMode_createUser_callsAdminApiFirstAndNeverStoresPassword() {
        RoleEntity agentRole = RoleEntity.builder().id(2L).name("ROLE_AGENT").build();
        when(userRepository.existsByUsernameAndDeletedAtIsNull("kc-agent")).thenReturn(false);
        when(roleRepository.findByName("ROLE_AGENT")).thenReturn(Optional.of(agentRole));
        when(keycloakAdminClient.createUser("kc-agent", "kc@incert.local", "KC Agent", true))
                .thenReturn("kc-sub-123");
        when(userRepository.findByExternalId("kc-sub-123")).thenReturn(Optional.empty());
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserDto dto = keycloakIdentityService.createUser(new CreateUserRequest(
                "kc-agent", "kc@incert.local", "KC Agent", null, true, "default", List.of("ROLE_AGENT")));

        assertThat(dto.externalId()).isEqualTo("kc-sub-123");
        assertThat(dto.authSource()).isEqualTo(AuthSource.KEYCLOAK);
        verify(keycloakAdminClient).createUser("kc-agent", "kc@incert.local", "KC Agent", true);

        ArgumentCaptor<UserEntity> savedCaptor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository).save(savedCaptor.capture());
        assertThat(savedCaptor.getValue().getPasswordHash()).isNull();

        assertThatThrownBy(() -> keycloakIdentityService.createUser(new CreateUserRequest(
                "kc-agent2", "kc2@incert.local", "KC Agent 2", "forbidden-pw", true, "default", List.of("ROLE_AGENT"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("owned by Keycloak");
    }

    @Test
    void keycloakSync_jitProvisioningIsIdempotentByExternalId() {
        RoleEntity auditorRole = RoleEntity.builder().id(3L).name("ROLE_AUDITOR").build();
        when(roleRepository.findByName("ROLE_AUDITOR")).thenReturn(Optional.of(auditorRole));
        when(userRepository.existsByUsernameAndDeletedAtIsNull("jdoe")).thenReturn(false);

        UserEntity existing = UserEntity.builder()
                .id("uuid-1")
                .externalId("sub-999")
                .authSource(AuthSource.KEYCLOAK)
                .username("jdoe")
                .email("old@incert.local")
                .roles(Set.of(auditorRole))
                .build();

        when(userRepository.findByExternalId("sub-999"))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(existing));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserEntity first = keycloakSyncService.upsertFromTokenClaims(
                "sub-999", "jdoe", "old@incert.local", true, "John Doe", List.of("ROLE_AUDITOR"));
        UserEntity second = keycloakSyncService.upsertFromTokenClaims(
                "sub-999", "jdoe", "new@incert.local", true, "Johnathan Doe", List.of("ROLE_AUDITOR"));

        assertThat(first.getExternalId()).isEqualTo("sub-999");
        assertThat(second.getId()).isEqualTo("uuid-1");
        assertThat(second.getEmail()).isEqualTo("new@incert.local");
        assertThat(second.getFullName()).isEqualTo("Johnathan Doe");
        assertThat(second.getPasswordHash()).isNull();
    }

    @Test
    void deleteUser_rejectsDeletingSelf() {
        RoleEntity adminRole = RoleEntity.builder().id(1L).name("ROLE_ADMIN").build();
        UserEntity admin = UserEntity.builder()
                .id("uuid-admin").authSource(AuthSource.LOCAL).username("admin").passwordHash("hash").enabled(true).roles(Set.of(adminRole)).build();
        when(userRepository.findById("uuid-admin")).thenReturn(Optional.of(admin));

        assertThatThrownBy(() -> localIdentityService.deleteUser("uuid-admin", false, "admin"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("your own account");
    }
}
