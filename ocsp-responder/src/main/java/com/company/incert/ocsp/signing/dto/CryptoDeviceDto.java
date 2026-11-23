package com.company.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Schema(description = "DB-configured HSM device / token slot combined with live Pattern 2 runtime activation status")
public record CryptoDeviceDto(
        Long id,
        String deviceId,
        Long providerId,
        String providerCode,
        String providerName,
        String wrapperType,
        String libraryPath,
        String libraryWrapperPath,
        String tokenLabel,
        Long slotId,
        int slotListIndex,
        int poolSize,
        boolean prehashInJvm,
        boolean isDefault,
        boolean enabled,
        String activationState,
        boolean healthy,
        String statusMessage,
        List<String> keyLabels,
        Map<String, String> keyAlgorithms,
        Instant createdAt,
        Instant updatedAt
) {}

