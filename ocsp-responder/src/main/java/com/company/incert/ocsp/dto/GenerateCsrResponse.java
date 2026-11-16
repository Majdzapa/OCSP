package com.company.incert.ocsp.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Generated PKCS#10 Certificate Signing Request (CSR) in PEM format")
public record GenerateCsrResponse(
    @Schema(description = "HSM key label used to sign the CSR", example = "ocsp-signing-key-2027")
    String keyLabel,

    @Schema(description = "Subject DN included in the CSR", example = "CN=Incert Delegated OCSP Signer,O=Incert,C=CH")
    String subjectDn,

    @Schema(description = "Key algorithm", example = "RSA")
    String keyAlgorithm,

    @Schema(description = "PEM-encoded PKCS#10 CSR")
    String csrPem
) {}

