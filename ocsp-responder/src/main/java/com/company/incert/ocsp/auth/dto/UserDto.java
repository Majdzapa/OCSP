package com.company.incert.ocsp.auth.dto;

import com.company.incert.ocsp.auth.entity.AuthSource;

import java.time.Instant;
import java.util.List;

public record UserDto(
    String id,
    String externalId,
    AuthSource authSource,
    String username,
    String email,
    boolean emailVerified,
    String fullName,
    boolean enabled,
    String tenantId,
    List<String> roles,
    Instant createdAt,
    Instant updatedAt
) {}
