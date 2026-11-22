package com.company.incert.ocsp.dto;

import com.company.incert.ocsp.entity.AuthSource;

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
