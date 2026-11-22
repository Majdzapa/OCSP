package com.company.incert.ocsp.service;

import com.company.incert.ocsp.config.AdminProperties;
import com.company.incert.ocsp.config.AdminUserInitializer;
import com.company.incert.ocsp.dto.CreateUserRequest;
import com.company.incert.ocsp.dto.UserDto;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserManagementServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    private PasswordEncoder passwordEncoder;
    private UserManagementService userManagementService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        userManagementService = new UserManagementService(userRepository, roleRepository, passwordEncoder);
    }

    @Test
    void initializer_createsBuiltInAdminFromPropertiesWhenAbsent() {
        AdminProperties props = new AdminProperties();
        props.setUsername("admin");
        props.setPassword("secret123");

        RoleEntity adminRole = RoleEntity.builder().id(1L).name("ROLE_ADMIN").build();
        when(roleRepository.findByName("ROLE_ADMIN")).thenReturn(Optional.of(adminRole));
        when(roleRepository.findByName("ROLE_AGENT")).thenReturn(Optional.of(RoleEntity.builder().id(2L).name("ROLE_AGENT").build()));
        when(roleRepository.findByName("ROLE_AUDITOR")).thenReturn(Optional.of(RoleEntity.builder().id(3L).name("ROLE_AUDITOR").build()));
        when(userRepository.findByUsername("admin")).thenReturn(Optional.empty());
        when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        AdminUserInitializer initializer = new AdminUserInitializer(userRepository, roleRepository, passwordEncoder, props);
        initializer.initializeBuiltInAdmin();

        ArgumentCaptor<UserEntity> captor = ArgumentCaptor.forClass(UserEntity.class);
        verify(userRepository).save(captor.capture());
        UserEntity saved = captor.getValue();
        assertThat(saved.getUsername()).isEqualTo("admin");
        assertThat(passwordEncoder.matches("secret123", saved.getPasswordHash())).isTrue();
        assertThat(saved.isEnabled()).isTrue();
        assertThat(saved.getRoles()).extracting(RoleEntity::getName).containsExactly("ROLE_ADMIN");
    }

    @Test
    void createUser_normalizesRoleAndEncodesPassword() {
        RoleEntity agentRole = RoleEntity.builder().id(2L).name("ROLE_AGENT").build();
        when(userRepository.existsByUsername("agent1")).thenReturn(false);
        when(roleRepository.findByName("ROLE_AGENT")).thenReturn(Optional.of(agentRole));
        when(userRepository.save(any())).thenAnswer(inv -> {
            UserEntity u = inv.getArgument(0);
            u.setId(10L);
            return u;
        });

        UserDto dto = userManagementService.createUser(new CreateUserRequest("agent1", "pass123", true, List.of("AGENT")));

        assertThat(dto.id()).isEqualTo(10L);
        assertThat(dto.username()).isEqualTo("agent1");
        assertThat(dto.roles()).containsExactly("ROLE_AGENT");
        assertThat(dto.enabled()).isTrue();
    }

    @Test
    void deleteUser_rejectsDeletingSelfOrLastAdmin() {
        RoleEntity adminRole = RoleEntity.builder().id(1L).name("ROLE_ADMIN").build();
        UserEntity admin = UserEntity.builder()
                .id(1L).username("admin").passwordHash("hash").enabled(true).roles(Set.of(adminRole)).build();
        when(userRepository.findById(1L)).thenReturn(Optional.of(admin));

        assertThatThrownBy(() -> userManagementService.deleteUser(1L, "admin"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("your own account");
    }
}

