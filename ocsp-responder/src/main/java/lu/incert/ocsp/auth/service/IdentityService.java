package lu.incert.ocsp.auth.service;

import lu.incert.ocsp.auth.dto.CreateUserRequest;
import lu.incert.ocsp.auth.dto.RoleDto;
import lu.incert.ocsp.auth.dto.UpdateUserRequest;
import lu.incert.ocsp.auth.dto.UserDto;

import java.util.List;

/**
 * Strategy interface for identity &amp; user management.
 * Exactly one implementation is active per deployment based on {@code app.auth.mode}:
 * <ul>
 *   <li>{@code LocalIdentityService} when {@code app.auth.mode=SELF_MANAGEMENT}</li>
 *   <li>{@code KeycloakIdentityService} when {@code app.auth.mode=KEYCLOAK}</li>
 * </ul>
 */
public interface IdentityService {

    List<UserDto> listUsers();

    List<RoleDto> listRoles();

    UserDto createUser(CreateUserRequest request);

    UserDto updateUser(String userId, UpdateUserRequest request, String actingUsername);

    UserDto setEnabled(String userId, boolean enabled, String actingUsername);

    void resetPassword(String userId, String newPassword);

    void deleteUser(String userId, boolean anonymizeGdpr, String actingUsername);
}

