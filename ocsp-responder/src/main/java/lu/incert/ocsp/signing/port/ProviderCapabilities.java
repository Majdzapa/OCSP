package lu.incert.ocsp.signing.port;

import java.util.List;
import java.util.Map;

/**
 * Live cryptographic capabilities reported by a signing provider/device (e.g. via PKCS#11
 * {@code C_GetMechanismList} and {@code C_GetMechanismInfo}).
 */
public record ProviderCapabilities(
        String providerId,
        boolean liveIntrospected,
        String statusMessage,
        List<KeyAlgorithmCapability> keyAlgorithms,
        Map<String, List<String>> supportedSignatureAlgorithms,
        List<SignatureAlgorithmCapability> signatureAlgorithms
) {
    public record KeyAlgorithmCapability(
            String keyAlgorithm,
            boolean supported,
            List<Integer> supportedKeySizes,
            long minKeySize,
            long maxKeySize,
            String mechanismName,
            String reason
    ) {}

    public record SignatureAlgorithmCapability(
            String algorithm,
            String keyType,
            boolean supported,
            String mechanismName,
            String reason
    ) {}

    public record AlgorithmValidationResult(
            boolean supported,
            String providerId,
            String resolvedKeyAlgorithm,
            Integer keySize,
            String signatureAlgorithm,
            String requiredMechanism,
            List<String> compatibleSupportedAlgorithms,
            String message
    ) {}
}

