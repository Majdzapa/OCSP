package lu.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Result of initializing a PKCS#11 token / creating a new virtual slot (Vslot)")
public record InitializeTokenResponse(
        CryptoSlotDto slot,
        CryptoDeviceDto registeredDevice,
        String message
) {}

