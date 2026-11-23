package com.company.incert.ocsp.signing.provider;

import com.company.incert.ocsp.signing.hsm.Pkcs11OcspSigner;
import com.company.incert.ocsp.signing.port.CryptoProviderPort;
import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;

import java.util.List;
import java.util.Map;

/**
 * {@link CryptoProviderPort} adapter wrapping the local {@code SunPKCS11}-based {@link Pkcs11OcspSigner}.
 */
public class SunPkcs11CryptoProviderAdapter implements CryptoProviderPort {

    private final String providerId;
    private final Pkcs11OcspSigner delegate;

    public SunPkcs11CryptoProviderAdapter(String providerId, Pkcs11OcspSigner delegate) {
        this.providerId = providerId;
        this.delegate = delegate;
    }

    @Override
    public String providerId() {
        return providerId;
    }

    @Override
    public String providerType() {
        return delegate.type();
    }

    @Override
    public ProviderDeviceInfo getDeviceInfo() {
        List<String> labels = delegate.listKeyLabels();
        Map<String, String> algs = delegate.getKeyAlgorithms();
        return new ProviderDeviceInfo(
                providerId,
                delegate.type(),
                delegate.getLibraryPath() != null ? delegate.getLibraryPath() : "",
                delegate.getTokenLabel() != null ? delegate.getTokenLabel() : "",
                delegate.getSlotListIndex(),
                true,
                "UP (SunPKCS11 slotIndex=" + delegate.getSlotListIndex() + ")",
                labels,
                algs
        );
    }

    @Override
    public List<String> listKeyLabels() {
        return delegate.listKeyLabels();
    }

    @Override
    public Map<String, String> getKeyAlgorithms() {
        return delegate.getKeyAlgorithms();
    }

    @Override
    public String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
        return delegate.generateCsr(keyLabel, subjectDn, keyAlgorithm, keySize, reuseExistingKey);
    }

    @Override
    public void importCertificate(String keyLabel, X509CertificateHolder certificate) {
        delegate.importCertificateToToken(keyLabel, certificate);
    }

    @Override
    public byte[] sign(String keyLabel, String signatureAlgorithm, byte[] data) {
        try {
            ContentSigner cs = delegate.createContentSigner(keyLabel, signatureAlgorithm);
            cs.getOutputStream().write(data);
            return cs.getSignature();
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("SunPKCS11 signing failed for key '" + keyLabel + "'", e);
        }
    }

    @Override
    public ContentSigner createContentSigner(String keyLabel, String signatureAlgorithm) {
        try {
            return delegate.createContentSigner(keyLabel, signatureAlgorithm);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed creating SunPKCS11 ContentSigner for key '" + keyLabel + "'", e);
        }
    }
}

