package lu.incert.ocsp.signing.dto;

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
    Boolean activateImmediately,

    @Schema(description = "Signature algorithm to use when signing OCSP responses with this certificate (e.g. SHA256withRSA, SHA384withRSA, SHA512withRSA, SHA256withECDSA, SHA384withECDSA)", example = "SHA256withRSA")
    String signatureAlgorithm,

    @Schema(description = "Signing provider/device ID in PkcsProviders (defaults to default provider if omitted)", example = "softhsm-primary")
    String providerId
) {
    public AddSigningCertificateRequest(String alias, String keyLabel, String certificatePem, Boolean activateImmediately) {
        this(alias, keyLabel, certificatePem, activateImmediately, null, null);
    }

    public AddSigningCertificateRequest(
            String alias,
            String keyLabel,
            String certificatePem,
            Boolean activateImmediately,
            String signatureAlgorithm) {
        this(alias, keyLabel, certificatePem, activateImmediately, signatureAlgorithm, null);
    }
}
