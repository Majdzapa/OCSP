package com.company.incert.ocsp.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

public record CreateUserRequest(
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 100, message = "Username must be between 3 and 100 characters")
    String username,

    @Email(message = "Invalid email format")
    String email,

    String fullName,

    /** Required in SELF_MANAGEMENT mode; ignored/forbidden in KEYCLOAK mode. */
    @Size(min = 4, max = 128, message = "Password must be at least 4 characters")
    String password,

    Boolean enabled,

    String tenantId,

    @NotEmpty(message = "At least one role is required")
    List<String> roles
) {}
