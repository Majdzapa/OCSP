package com.company.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(description = "Cryptographic HSM driver & JNI wrapper configuration stored in crypto_providers")
public record CryptoProviderDto(
        Long id,
        String code,
        String name,
        String wrapperType,
        String libraryPath,
        String libraryWrapperPath,
        boolean enabled,
        long deviceCount,
        Instant createdAt,
        Instant updatedAt
) {}

