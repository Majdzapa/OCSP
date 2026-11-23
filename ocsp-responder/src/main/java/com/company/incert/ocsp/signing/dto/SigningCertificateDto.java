package com.company.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

import java.time.Instant;

@Builder
@Schema(description = "Details of a signing certificate registered in the OCSP responder")
public record SigningCertificateDto(
    @Schema(description = "Database ID", example = "1")
    Long id,

    @Schema(description = "Human-readable unique alias", example = "ocsp-signing-2026")
    String alias,

    @Schema(description = "Signing provider/device ID in PkcsProviders", example = "softhsm-primary")
    String providerId,

    @Schema(description = "Key alias / label in the HSM", example = "ocsp-signing-key")
    String keyLabel,

    @Schema(description = "Certificate Subject Distinguished Name", example = "CN=Incert Delegated OCSP Responder, O=Incert, C=CH")
    String subjectDn,

    @Schema(description = "Certificate Issuer Distinguished Name", example = "CN=Incert Root CA, O=Incert, C=CH")
    String issuerDn,

    @Schema(description = "Certificate Serial Number (hex)", example = "01fa23bc45")
    String serialNumber,

    @Schema(description = "Validity start time")
    Instant notBefore,

    @Schema(description = "Validity expiration time")
    Instant notAfter,

    @Schema(description = "Signature Algorithm", example = "SHA256withRSA")
    String signatureAlgorithm,

    @Schema(description = "Whether this is the currently active certificate used for signing responses", example = "true")
    boolean active,

    @Schema(description = "Days until certificate expiry", example = "29")
    long daysUntilExpiry,

    @Schema(description = "Whether the certificate has expired", example = "false")
    boolean expired,

    @Schema(description = "Creation timestamp")
    Instant createdAt,

    @Schema(description = "Activation timestamp")
    Instant activatedAt,

    @Schema(description = "Full PEM encoded certificate content")
    String certificatePem
) {
    public SigningCertificateDto(
            Long id,
            String alias,
            String keyLabel,
            String subjectDn,
            String issuerDn,
            String serialNumber,
            Instant notBefore,
            Instant notAfter,
            String signatureAlgorithm,
            boolean active,
            long daysUntilExpiry,
            boolean expired,
            Instant createdAt,
            Instant activatedAt,
            String certificatePem) {
        this(id, alias, "default", keyLabel, subjectDn, issuerDn, serialNumber, notBefore, notAfter,
                signatureAlgorithm, active, daysUntilExpiry, expired, createdAt, activatedAt, certificatePem);
    }
}

