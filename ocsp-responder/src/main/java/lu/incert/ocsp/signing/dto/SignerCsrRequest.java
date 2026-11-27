package lu.incert.ocsp.signing.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(description = "Optional overrides when generating a keypair & PKCS#10 CSR for a Signer")
public record SignerCsrRequest(
        @Schema(description = "If true, reuse an existing private key in the HSM Token instead of generating a new keypair", defaultValue = "false")
        Boolean reuseExistingKey,

        @Schema(description = "Optional target HSM Token deviceId from the signer's token list (defaults to primary / first ACTIVE token)")
        String tokenDeviceId,

        @Schema(description = "Optional Subject DN override (defaults to signer's subjectDn)")
        String subjectDn,

        @Schema(description = "Optional key algorithm override (defaults to signer's keyAlgorithm)")
        String keyAlgorithm,

        @Schema(description = "Optional key size override (defaults to signer's keySize)")
        Integer keySize,

        @Schema(description = "Optional CSR signature algorithm override (defaults to signer's signatureAlgorithm)")
        String signatureAlgorithm
) {
    public record SignerCsrResponse(
            Long signerId,
            String signerCode,
            String tokenDeviceId,
            Long keyId,
            String keyLabel,
            String keyAlgorithm,
            int keySize,
            String publicKeySha1,
            String signatureAlgorithm,
            String subjectDn,
            String csrPem,
            Instant generatedAt
    ) {}
}
