package com.company.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Transient runtime-unlock request payload. Custom {@link #toString()} prevents accidental PIN logging.
 */
@Schema(description = "Transient HSM user PIN payload for Pattern 2 runtime activation (never persisted)")
public record ActivateCryptoDeviceRequest(
        @NotBlank(message = "HSM PIN is required")
        @Schema(description = "PKCS#11 user PIN held transiently in memory only during C_Login", format = "password")
        String pin
) {
    @Override
    public String toString() {
        return "ActivateCryptoDeviceRequest[pin=***]";
    }
}

