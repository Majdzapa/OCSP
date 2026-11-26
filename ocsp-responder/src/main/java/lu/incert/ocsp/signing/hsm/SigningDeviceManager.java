package lu.incert.ocsp.signing.hsm;

import lu.incert.ocsp.signing.port.ProviderCapabilities;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import org.bouncycastle.cert.X509CertificateHolder;

import java.util.List;
import java.util.Map;

/**
 * Administrative device/certificate lifecycle contract (Interface Segregation Principle).
 * Separates HSM provisioning, CSR generation, and cert activation from runtime OCSP signing.
 */
public interface SigningDeviceManager {

    default void updateActiveCertificate(String keyLabel, X509CertificateHolder certificate) {}

    default void updateActiveCertificate(String keyLabel, X509CertificateHolder certificate, String signatureAlgorithm) {
        updateActiveCertificate(keyLabel, certificate);
    }

    default void updateActiveCertificate(
            String providerId,
            String keyLabel,
            X509CertificateHolder certificate,
            String signatureAlgorithm) {
        updateActiveCertificate(keyLabel, certificate, signatureAlgorithm);
    }

    default String getDefaultProviderId() {
        return "default";
    }

    default String getActiveProviderId() {
        return getDefaultProviderId();
    }

    default List<ProviderDeviceInfo> listProviders() {
        return List.of();
    }

    default String getActiveKeyLabel() {
        return "ocsp-signing-key";
    }

    default List<String> listKeyLabels() {
        return List.of(getActiveKeyLabel());
    }

    default List<String> listKeyLabels(String providerId) {
        return listKeyLabels();
    }

    default Map<String, String> getKeyAlgorithms() {
        return Map.of();
    }

    default String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
        throw new UnsupportedOperationException("CSR generation is only supported when PKCS#11 HSM is enabled");
    }

    default String generateCsr(
            String providerId,
            String keyLabel,
            String subjectDn,
            String keyAlgorithm,
            int keySize,
            boolean reuseExistingKey) {
        return generateCsr(keyLabel, subjectDn, keyAlgorithm, keySize, reuseExistingKey);
    }

    default String generateCsr(
            String providerId,
            String keyLabel,
            String subjectDn,
            String keyAlgorithm,
            int keySize,
            String signatureAlgorithm,
            boolean reuseExistingKey) {
        return generateCsr(providerId, keyLabel, subjectDn, keyAlgorithm, keySize, reuseExistingKey);
    }

    default ProviderCapabilities getProviderCapabilities(String providerId) {
        return new ProviderCapabilities(
                providerId != null ? providerId : getDefaultProviderId(),
                false,
                "Static software signer capabilities",
                List.of(),
                SigningAlgorithm.groupedByKeyType(),
                List.of()
        );
    }

    default ProviderCapabilities.AlgorithmValidationResult checkAlgorithmSupport(
            String providerId,
            String keyLabel,
            String keyAlgorithm,
            Integer keySize,
            String signatureAlgorithm) {
        String keyType = (keyAlgorithm != null && !keyAlgorithm.isBlank()) ? keyAlgorithm.trim().toUpperCase() : "RSA";
        List<String> compatible = SigningAlgorithm.namesForKeyType(keyType);
        boolean ok = signatureAlgorithm == null || signatureAlgorithm.isBlank()
                ? !compatible.isEmpty()
                : SigningAlgorithm.isSupportedForKeyType(signatureAlgorithm.trim(), keyType);
        return new ProviderCapabilities.AlgorithmValidationResult(
                ok,
                providerId != null ? providerId : getDefaultProviderId(),
                keyType,
                keySize,
                signatureAlgorithm,
                null,
                compatible,
                ok ? "Supported by software signer"
                   : "Unsupported algorithm '" + signatureAlgorithm + "' for key type " + keyType + ". Allowed: " + compatible
        );
    }

    default void importCertificateToToken(String keyLabel, X509CertificateHolder certificate) {}

    default void importCertificateToToken(String providerId, String keyLabel, X509CertificateHolder certificate) {
        importCertificateToToken(keyLabel, certificate);
    }

    default void syncRegisteredSigners(List<RegisteredSigner> signers) {}

    record RegisteredSigner(
            String providerId,
            List<String> providerIds,
            String keyLabel,
            X509CertificateHolder certificate,
            boolean preferred,
            String signatureAlgorithm) {

        public RegisteredSigner(
                String providerId,
                String keyLabel,
                X509CertificateHolder certificate,
                boolean preferred,
                String signatureAlgorithm) {
            this(providerId,
                 providerId != null ? List.of(providerId) : List.of("default"),
                 keyLabel, certificate, preferred, signatureAlgorithm);
        }

        public RegisteredSigner(String keyLabel, X509CertificateHolder certificate, boolean preferred, String signatureAlgorithm) {
            this("default", List.of("default"), keyLabel, certificate, preferred, signatureAlgorithm);
        }

        public RegisteredSigner(String keyLabel, X509CertificateHolder certificate, boolean preferred) {
            this("default", List.of("default"), keyLabel, certificate, preferred, null);
        }
    }
}

