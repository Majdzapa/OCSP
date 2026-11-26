package lu.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Payload to add a new signing certificate to the responder (either by signerId or by explicit alias/provider/keyLabel)")
public record AddSigningCertificateRequest(
    @Schema(description = "Unique human-readable alias for this certificate (auto-populated from Signer code if signerId is provided)", example = "550e8400-e29b-41d4-a716-446655440000")
    String alias,

    @Schema(description = "Key label in HSM (auto-populated from Signer keyLabel if signerId is provided)", example = "a87ff679-a2f3-4e71-d918-1a67b7542122")
    String keyLabel,

    @NotBlank(message = "Certificate PEM content is required")
    @Schema(description = "PEM encoded X.509 certificate", example = "-----BEGIN CERTIFICATE-----\nMIID...")
    String certificatePem,

    @Schema(description = "Whether to immediately activate this certificate for signing responses", defaultValue = "false")
    Boolean activateImmediately,

    @Schema(description = "Signature algorithm to use when signing OCSP responses with this certificate (auto-populated from Signer if signerId is provided)", example = "SHA256withRSA")
    String signatureAlgorithm,

    @Schema(description = "Signing provider/device ID in PkcsProviders (auto-populated from Signer's ordered Vslots if signerId is provided)", example = "softhsm-primary")
    String providerId,

    @Schema(description = "Optional OCSP Signer ID (`ocsp_signers.id`); when provided, imports the certificate into the Signer and its bound HSM Vslots", example = "1")
    Long signerId
) {
    public AddSigningCertificateRequest(String alias, String keyLabel, String certificatePem, Boolean activateImmediately) {
        this(alias, keyLabel, certificatePem, activateImmediately, null, null, null);
    }

    public AddSigningCertificateRequest(
            String alias,
            String keyLabel,
            String certificatePem,
            Boolean activateImmediately,
            String signatureAlgorithm) {
        this(alias, keyLabel, certificatePem, activateImmediately, signatureAlgorithm, null, null);
    }

    public AddSigningCertificateRequest(
            String alias,
            String keyLabel,
            String certificatePem,
            Boolean activateImmediately,
            String signatureAlgorithm,
            String providerId) {
        this(alias, keyLabel, certificatePem, activateImmediately, signatureAlgorithm, providerId, null);
    }
}

