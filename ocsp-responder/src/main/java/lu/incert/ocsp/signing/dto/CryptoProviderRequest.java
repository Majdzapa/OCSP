package lu.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "Request to create or update a PKCS#11 cryptographic provider (library + libraryWrapper)")
public record CryptoProviderRequest(
        @NotBlank(message = "Provider code is required")
        @Size(max = 64)
        @Schema(description = "Unique short identifier", example = "softhsm2")
        String code,

        @NotBlank(message = "Provider name is required")
        @Size(max = 150)
        @Schema(description = "Human-readable name", example = "SoftHSM v2 (PKCS11J)")
        String name,

        @Size(max = 40)
        @Schema(description = "Wrapper strategy type (e.g. PKCS11J)", example = "PKCS11J")
        String wrapperType,

        @NotBlank(message = "PKCS#11 vendor libraryPath is required")
        @Size(max = 500)
        @Schema(description = "Absolute path to vendor Cryptoki .so/.dylib inside allowlisted directories", example = "/usr/lib/softhsm/libsofthsm2.so")
        String libraryPath,

        @Size(max = 500)
        @Schema(description = "Absolute path to JNI wrapper binary inside allowlisted directories", example = "/opt/pkcs11j/libpkcs11wrapper.so")
        String libraryWrapperPath,

        @Schema(description = "Whether devices using this provider can be unlocked", example = "true")
        Boolean enabled
) {}

