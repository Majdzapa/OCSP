package com.company.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Schema(description = "Request to create or update a crypto device / HSM slot (Pattern 2: zero PIN stored)")
public record CryptoDeviceRequest(
        @NotBlank(message = "deviceId is required")
        @Size(max = 100)
        @Schema(description = "Unique device identifier referenced by signing certificates", example = "softhsm-primary")
        String deviceId,

        @NotNull(message = "providerId is required")
        @Schema(description = "Foreign key ID of the crypto_providers row", example = "1")
        Long providerId,

        @Size(max = 150)
        @Schema(description = "PKCS#11 token label (used to resolve slot ID if slotId is null)", example = "ocsp-signing")
        String tokenLabel,

        @Schema(description = "Explicit PKCS#11 numeric slot ID (optional; overrides tokenLabel/slotListIndex if set)")
        Long slotId,

        @Min(0)
        @Schema(description = "Zero-based slot list index fallback when slotId and tokenLabel are omitted", example = "0")
        Integer slotListIndex,

        @Min(1)
        @Schema(description = "Number of pooled PKCS#11 RO sessions opened upon runtime unlock", example = "4")
        Integer poolSize,

        @Schema(description = "Whether to compute SHA-* digest in JVM before C_Sign", example = "false")
        Boolean prehashInJvm,

        @Schema(description = "Mark as default signing device in PkcsProviders", example = "false")
        Boolean isDefault,

        @Schema(description = "Whether the device is enabled", example = "true")
        Boolean enabled
) {}

