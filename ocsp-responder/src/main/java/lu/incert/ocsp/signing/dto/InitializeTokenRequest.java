package lu.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "Transient request to create a virtual slot (Vslot) or initialize a PKCS#11 token via C_InitToken + C_InitPIN. PINs are wiped immediately and never persisted.")
public record InitializeTokenRequest(
        @Schema(description = "Optional target PKCS#11 slot ID. Leave null to auto-select a free uninitialized slot (creates a new Vslot on SoftHSM2).", example = "0")
        Long slotId,

        @NotBlank(message = "Token label is required")
        @Size(max = 32, message = "Token label must be at most 32 characters (PKCS#11 limit)")
        @Schema(description = "Human-readable PKCS#11 token label (1..32 characters)", example = "ocsp-ca-3")
        String tokenLabel,

        @NotBlank(message = "Security Officer (SO) PIN is required")
        @Schema(description = "Transient Security Officer PIN used for C_InitToken and C_Login(CKU_SO); wiped immediately", example = "12345678")
        String soPin,

        @NotBlank(message = "User PIN is required")
        @Schema(description = "Transient normal User PIN set via C_InitPIN; wiped immediately and never stored", example = "1234")
        String userPin,

        @Schema(description = "If true, also register the newly initialized token as an OCSP Crypto Device in LOCKED state (Pattern 2)", defaultValue = "true")
        Boolean registerAsDevice,

        @Schema(description = "Optional custom deviceId when registerAsDevice=true (auto-generated from providerCode + tokenLabel if blank)", example = "softhsm2-ocsp-ca-3")
        String deviceId,

        @Schema(description = "Optional PKCS#11 session pool size when registerAsDevice=true", defaultValue = "4")
        Integer poolSize,

        @Schema(description = "Whether the registered device should be marked as default", defaultValue = "false")
        Boolean isDefault
) {}

