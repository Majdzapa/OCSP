package com.company.incert.ocsp.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Payload to add a new signing certificate to the responder")
public record AddSigningCertificateRequest(
    @NotBlank(message = "Alias is required")
    @Schema(description = "Unique human-readable alias for this certificate", example = "ocsp-signing-2027")
    String alias,

    @Schema(description = "Key label in HSM (defaults to active key label if omitted)", example = "ocsp-signing-key")
    String keyLabel,

    @NotBlank(message = "Certificate PEM content is required")
    @Schema(description = "PEM encoded X.509 certificate", example = "-----BEGIN CERTIFICATE-----\nMIID...")
    String certificatePem,

    @Schema(description = "Whether to immediately activate this certificate for signing responses", defaultValue = "false")
    Boolean activateImmediately
) {}

