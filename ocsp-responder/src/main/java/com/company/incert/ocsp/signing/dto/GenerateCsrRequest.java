package com.company.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Request to generate a PKCS#10 Certificate Signing Request (CSR) from an HSM keypair")
public record GenerateCsrRequest(
    @NotBlank(message = "Key label is required")
    @Schema(description = "HSM key label (new label to generate a keypair, or existing label when reuseExistingKey=true)", example = "ocsp-signing-key-2027")
    String keyLabel,

    @NotBlank(message = "Subject DN is required")
    @Schema(description = "X.500 Subject Distinguished Name for the CSR", example = "CN=Incert Delegated OCSP Signer,O=Incert,C=CH")
    String subjectDn,

    @Schema(description = "Key algorithm: RSA or EC", example = "RSA", defaultValue = "RSA")
    String keyAlgorithm,

    @Schema(description = "Key size in bits (2048, 3072, 4096 for RSA; 256, 384 for EC)", example = "3072", defaultValue = "3072")
    Integer keySize,

    @Schema(description = "If true, reuse an existing private key in the HSM token instead of generating a new keypair", defaultValue = "false")
    Boolean reuseExistingKey
) {}

