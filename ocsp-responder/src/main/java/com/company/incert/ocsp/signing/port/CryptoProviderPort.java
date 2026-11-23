package com.company.incert.ocsp.signing.port;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;

import java.util.List;
import java.util.Map;

/**
 * Hexagonal port abstracting a cryptographic signing device (remote PKCS11J over gRPC,
 * local SunPKCS11 token, hardware HSM, or software fallback).
 */
public interface CryptoProviderPort extends AutoCloseable {

    String providerId();

    String providerType();

    ProviderDeviceInfo getDeviceInfo();

    List<String> listKeyLabels();

    Map<String, String> getKeyAlgorithms();

    String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey);

    void importCertificate(String keyLabel, X509CertificateHolder certificate);

    byte[] sign(String keyLabel, String signatureAlgorithm, byte[] data);

    default ContentSigner createContentSigner(String keyLabel, String signatureAlgorithm) {
        return new BufferedContentSigner(signatureAlgorithm, bytes -> sign(keyLabel, signatureAlgorithm, bytes));
    }

    @Override
    default void close() {}
}

