package lu.incert.ocsp.signing.port;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Hexagonal port abstracting a cryptographic signing device (in-process PKCS#11 via {@code ipkcs11wrapper},
 * external KMS/KMIP provider, or software fallback).
 */
public interface CryptoProviderPort extends AutoCloseable {

    String providerId();

    String providerType();

    ProviderDeviceInfo getDeviceInfo();

    List<String> listKeyLabels();

    Map<String, String> getKeyAlgorithms();

    /**
     * Explicit on-demand read of a token key's {@link SubjectPublicKeyInfo} (used only during manual key sync).
     */
    default Optional<SubjectPublicKeyInfo> readPublicKeyInfo(String keyLabel) {
        return Optional.empty();
    }

    String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey);

    default String generateCsr(
            String keyLabel,
            String subjectDn,
            String keyAlgorithm,
            int keySize,
            String signatureAlgorithm,
            boolean reuseExistingKey) {
        return generateCsr(keyLabel, subjectDn, keyAlgorithm, keySize, reuseExistingKey);
    }

    /**
     * Queries live key/signature algorithm capabilities supported by this device.
     */
    default ProviderCapabilities getCapabilities() {
        return new ProviderCapabilities(
                providerId(),
                false,
                "Static capabilities (live mechanism introspection not implemented by provider type " + providerType() + ")",
                List.of(),
                Map.of(),
                List.of()
        );
    }

    /**
     * Checks whether a key algorithm / key size / key label and signature algorithm are supported
     * by this provider before signing or generating keys.
     */
    default ProviderCapabilities.AlgorithmValidationResult checkAlgorithmSupport(
            String keyLabel,
            String keyAlgorithm,
            Integer keySize,
            String signatureAlgorithm) {
        return new ProviderCapabilities.AlgorithmValidationResult(
                false,
                providerId(),
                keyAlgorithm,
                keySize,
                signatureAlgorithm,
                null,
                List.of(),
                "Live algorithm support check is not implemented by provider '" + providerId() + "' (" + providerType() + ")"
        );
    }

    void importCertificate(String keyLabel, X509CertificateHolder certificate);

    byte[] sign(String keyLabel, String signatureAlgorithm, byte[] data);

    default ContentSigner createContentSigner(String keyLabel, String signatureAlgorithm) {
        return new BufferedContentSigner(signatureAlgorithm, bytes -> sign(keyLabel, signatureAlgorithm, bytes));
    }

    @Override
    default void close() {}
}

