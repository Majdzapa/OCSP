package com.company.incert.ocsp.signing.hsm;

import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
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

    default void importCertificateToToken(String keyLabel, X509CertificateHolder certificate) {}

    default void importCertificateToToken(String providerId, String keyLabel, X509CertificateHolder certificate) {
        importCertificateToToken(keyLabel, certificate);
    }

    default void syncRegisteredSigners(List<RegisteredSigner> signers) {}

    record RegisteredSigner(
            String providerId,
            String keyLabel,
            X509CertificateHolder certificate,
            boolean preferred,
            String signatureAlgorithm) {

        public RegisteredSigner(String keyLabel, X509CertificateHolder certificate, boolean preferred, String signatureAlgorithm) {
            this("default", keyLabel, certificate, preferred, signatureAlgorithm);
        }

        public RegisteredSigner(String keyLabel, X509CertificateHolder certificate, boolean preferred) {
            this("default", keyLabel, certificate, preferred, null);
        }
    }
}

