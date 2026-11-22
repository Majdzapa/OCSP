package com.company.incert.ocsp.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

import java.util.List;

public record UpdateUserRequest(
    @Email(message = "Invalid email format")
    String email,

    String fullName,

    /** Allowed in SELF_MANAGEMENT mode only; ignored/rejected in KEYCLOAK mode. */
    @Size(min = 4, max = 128, message = "Password must be at least 4 characters")
    String password,

    Boolean enabled,

    String tenantId,

    List<String> roles
) {}
