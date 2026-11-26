package lu.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

@Schema(description = "Request payload to create or update an OCSP Signer with its ordered HSM Vslots, key policy, and signing algorithm")
public record SignerRequest(
        @Schema(description = "Unique signer code (UUID; auto-generated if omitted or blank)", example = "550e8400-e29b-41d4-a716-446655440000")
        String code,

        @NotBlank(message = "Signer display name is required")
        @Schema(description = "Human-readable signer name", example = "Luxembourg Root CA OCSP Signer")
        String name,

        @NotBlank(message = "Subject DN is required")
        @Schema(description = "X.500 Subject Distinguished Name for the OCSP signing certificate", example = "CN=Incert OCSP Signer,O=Incert,C=LU")
        String subjectDn,

        @Schema(description = "Private key label in the bound HSM Vslot(s) (UUID; auto-generated if omitted or blank)", example = "a87ff679-a2f3-4e71-d918-1a67b7542122")
        String keyLabel,

        @NotBlank(message = "Key algorithm is required")
        @Schema(description = "Key algorithm (e.g. RSA, EC)", example = "RSA")
        String keyAlgorithm,

        @Schema(description = "Key size in bits (2048, 3072, 4096 for RSA; 256, 384, 521 for EC)", example = "3072")
        Integer keySize,

        @NotBlank(message = "Signature algorithm is required")
        @Schema(description = "Signature algorithm chosen by the user and verified against HSM mechanisms", example = "SHA256withRSA")
        String signatureAlgorithm,

        @NotEmpty(message = "At least one HSM Vslot (deviceId) must be bound to the signer")
        @Schema(description = "Ordered list of HSM Vslot deviceIds (index 0 = PRIMARY, 1..N = FAILOVER)", example = "[\"softhsm-primary\", \"softhsm-secondary\"]")
        List<String> vslotDeviceIds
) {}


