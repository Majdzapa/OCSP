package com.company.incert.ocsp.signing.dto;

import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;
import java.util.Map;

@Schema(description = "Configured PKCS#11 HSM information and available key labels")
public record HsmInfoDto(
    @Schema(description = "Active signer type (PKCS11J_GRPC, PKCS11, or SOFTWARE)", example = "PKCS11J_GRPC")
    String signerType,

    @Schema(description = "Configured PKCS#11 shared library path", example = "/usr/lib/softhsm/libsofthsm2.so")
    String pkcs11Library,

    @Schema(description = "Configured HSM token label", example = "ocsp-signing")
    String tokenLabel,

    @Schema(description = "Configured HSM slot ID or list index", example = "0")
    int slotIndex,

    @Schema(description = "Currently active HSM key label", example = "ocsp-signing-key")
    String activeKeyLabel,

    @Schema(description = "All key aliases currently present in the default HSM token")
    List<String> tokenAliases,

    @Schema(description = "Map of HSM key label -> key algorithm (e.g. RSA, EC)")
    Map<String, String> keyAlgorithms,

    @Schema(description = "Supported OCSP signature algorithms grouped by key algorithm (RSA, EC)")
    Map<String, List<String>> supportedSignatureAlgorithms,

    @Schema(description = "Default signing provider/device ID in PkcsProviders", example = "softhsm-primary")
    String defaultProviderId,

    @Schema(description = "All signing providers/devices connected simultaneously to PkcsProviders")
    List<ProviderDeviceInfo> providers
) {
    public HsmInfoDto(
            String signerType,
            String pkcs11Library,
            String tokenLabel,
            int slotIndex,
            String activeKeyLabel,
            List<String> tokenAliases,
            Map<String, String> keyAlgorithms,
            Map<String, List<String>> supportedSignatureAlgorithms) {
        this(signerType, pkcs11Library, tokenLabel, slotIndex, activeKeyLabel, tokenAliases,
                keyAlgorithms, supportedSignatureAlgorithms, "default", List.of());
    }
}
