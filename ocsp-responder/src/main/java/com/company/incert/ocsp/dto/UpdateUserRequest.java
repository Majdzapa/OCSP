package com.company.incert.ocsp.dto;

import jakarta.validation.constraints.Size;

import java.util.List;

public record UpdateUserRequest(
    @Size(min = 4, max = 128, message = "Password must be at least 4 characters")
    String password,

    Boolean enabled,

    List<String> roles
) {}

