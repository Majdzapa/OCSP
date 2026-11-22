package com.company.incert.ocsp.dto;

import java.time.Instant;
import java.util.List;

public record UserDto(
    Long id,
    String username,
    boolean enabled,
    List<String> roles,
    Instant createdAt,
    Instant updatedAt
) {}

