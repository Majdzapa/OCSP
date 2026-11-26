package lu.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Request to verify whether an HSM provider supports a selected key algorithm, key size, and signing algorithm")
public record AlgorithmCheckRequest(
        @Schema(description = "Target signing provider/device ID (defaults to default provider if omitted)", example = "softhsm-primary")
        String providerId,

        @Schema(description = "Optional existing HSM key label whose actual key type (RSA/EC) will be verified", example = "ocsp-signing-key")
        String keyLabel,

        @Schema(description = "Optional key algorithm to check (e.g. RSA, EC)", example = "RSA")
        String keyAlgorithm,

        @Schema(description = "Optional key size in bits (e.g. 2048, 3072, 4096 for RSA; 256, 384, 521 for EC)", example = "3072")
        Integer keySize,

        @Schema(description = "Signature algorithm to check (e.g. SHA256withRSA, SHA384withRSA, SHA256withRSAandMGF1, SHA256withECDSA)", example = "SHA256withRSA")
        String signatureAlgorithm
) {}

