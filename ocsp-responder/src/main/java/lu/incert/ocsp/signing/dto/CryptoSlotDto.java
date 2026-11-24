package lu.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Live PKCS#11 slot / token discovered from a cryptographic provider (no PIN required)")
public record CryptoSlotDto(
        @Schema(description = "Numeric PKCS#11 CK_SLOT_ID", example = "362291186")
        long slotId,

        @Schema(description = "Zero-based index in C_GetSlotList(true)", example = "0")
        int slotListIndex,

        @Schema(description = "Token label from C_GetTokenInfo().label", example = "ocsp-signing")
        String tokenLabel,

        @Schema(description = "Hardware/driver manufacturer ID", example = "SoftHSM project")
        String manufacturerId,

        @Schema(description = "Device/token model", example = "SoftHSM v2")
        String model,

        @Schema(description = "Token serial number", example = "a1b2c3d4e5f6")
        String serialNumber,

        @Schema(description = "True when CKF_TOKEN_INITIALIZED is set on C_GetTokenInfo().flags", example = "true")
        boolean initialized,

        @Schema(description = "Mapped crypto_devices.device_id if already registered under this provider", example = "softhsm-primary")
        String configuredDeviceId,

        @Schema(description = "Live runtime state (LOCKED, ACTIVE, DISABLED) if mapped, else null", example = "LOCKED")
        String configuredDeviceState
) {}

