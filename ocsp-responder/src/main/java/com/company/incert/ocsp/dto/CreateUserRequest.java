package com.company.incert.ocsp.dto;

import com.company.incert.ocsp.validation.PatternValidation;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

public record CreateUserRequest(
    @NotBlank(message = "Username is required")
    @Pattern(regexp = PatternValidation.USERNAME_REGEX, message = "Username must be 3-100 characters (letters, digits, ., _, -)")
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
