package com.company.incert.ocsp.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

public record CreateUserRequest(
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 100, message = "Username must be between 3 and 100 characters")
    String username,

    @NotBlank(message = "Password is required")
    @Size(min = 4, max = 128, message = "Password must be at least 4 characters")
    String password,

    Boolean enabled,

    @NotEmpty(message = "At least one role is required")
    List<String> roles
) {}

