package com.company.incert.ocsp.auth;

import com.company.incert.ocsp.auth.config.AdminProperties;
import com.company.incert.ocsp.auth.config.AdminUserInitializer;
import com.company.incert.ocsp.auth.config.AppAuthProperties;
import com.company.incert.ocsp.auth.dto.CreateUserRequest;
import com.company.incert.ocsp.auth.dto.UserDto;
import com.company.incert.ocsp.auth.entity.AuthSource;
import com.company.incert.ocsp.auth.entity.RoleEntity;
import com.company.incert.ocsp.auth.entity.UserEntity;
import com.company.incert.ocsp.auth.repository.RoleRepository;
import com.company.incert.ocsp.auth.repository.UserRepository;
import com.company.incert.ocsp.auth.service.LocalIdentityService;
import com.company.incert.ocsp.auth.service.UserDomainSupport;
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

    private PasswordEncoder passwordEncoder;
    private UserDomainSupport support;
    private LocalIdentityService localIdentityService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        support = new UserDomainSupport(userRepository, roleRepository);
        localIdentityService = new LocalIdentityService(userRepository, support, passwordEncoder);
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
    }

    @Test
    void localMode_createsUserWithHashedPassword() {
        RoleEntity agentRole = RoleEntity.builder().id(2L).name("ROLE_AGENT").build();
        when(userRepository.existsByUsernameAndDeletedAtIsNull("agent1")).thenReturn(false);
        when(roleRepository.findByName("ROLE_AGENT")).thenReturn(Optional.of(agentRole));
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        UserDto created = localIdentityService.createUser(new CreateUserRequest(
                "agent1", "agent1@incert.local", "Agent One", "pass1234", true, "org-a", List.of("AGENT")));

        assertThat(created.id()).isNotBlank();
        assertThat(created.authSource()).isEqualTo(AuthSource.LOCAL);
        assertThat(created.roles()).containsExactly("ROLE_AGENT");
    }

    @Test
    void localMode_rejectsBlankPasswordOnCreate() {
        when(userRepository.existsByUsernameAndDeletedAtIsNull("agent2")).thenReturn(false);
        assertThatThrownBy(() -> localIdentityService.createUser(new CreateUserRequest(
                "agent2", null, null, "", true, "default", List.of("AGENT"))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Password is required");
    }
}
