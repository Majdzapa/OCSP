package com.company.incert.ocsp.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

@Schema(description = "Configured PKCS#11 HSM information and available key labels")
public record HsmInfoDto(
    @Schema(description = "Active signer type (PKCS11 or SOFTWARE)", example = "PKCS11")
    String signerType,

    @Schema(description = "Configured PKCS#11 shared library path", example = "/usr/lib/softhsm/libsofthsm2.so")
    String pkcs11Library,

    @Schema(description = "Configured HSM token label", example = "ocsp-signing")
    String tokenLabel,

    @Schema(description = "Configured HSM slot list index", example = "0")
    int slotIndex,

    @Schema(description = "Currently active HSM key label", example = "ocsp-signing-key")
    String activeKeyLabel,

    @Schema(description = "All key aliases currently present in the HSM token")
    List<String> tokenAliases
) {}

