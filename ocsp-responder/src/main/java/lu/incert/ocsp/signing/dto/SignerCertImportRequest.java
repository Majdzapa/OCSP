package lu.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Payload to import a CA-signed X.509 certificate into an OCSP Signer and its bound HSM Vslot(s)")
public record SignerCertImportRequest(
        @NotBlank(message = "Certificate PEM content is required")
        @Schema(description = "PEM-encoded X.509 certificate signed by the issuing CA", example = "-----BEGIN CERTIFICATE-----\nMIID...")
        String certificatePem,

        @Schema(description = "Optional signature algorithm override (verified against live HSM mechanisms; defaults to signer's signatureAlgorithm)")
        String signatureAlgorithm,

        @Schema(description = "If true (ADMIN only), immediately activate this signer for live RFC 6960 OCSP responses", defaultValue = "true")
        Boolean activateImmediately
) {}

