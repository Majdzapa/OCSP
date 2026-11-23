package com.company.incert.ocsp.signing.provider;

import com.company.incert.hsm.grpc.v1.GenerateCsrRpcResponse;
import com.company.incert.hsm.grpc.v1.KeyDescriptor;
import com.company.incert.hsm.grpc.v1.ListKeysResponse;
import com.company.incert.hsm.grpc.v1.ListProvidersResponse;
import com.company.incert.hsm.grpc.v1.ProviderDescriptor;
import com.company.incert.ocsp.signing.port.CryptoProviderPort;
import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@link CryptoProviderPort} adapter delegating cryptographic operations for one remote HSM provider
 * over persistent gRPC to {@code hsm-signer}.
 */
@Slf4j
public class GrpcCryptoProviderAdapter implements CryptoProviderPort {

    private static final DefaultSignatureAlgorithmIdentifierFinder ALG_FINDER =
            new DefaultSignatureAlgorithmIdentifierFinder();

    private final String providerId;
    private final String remoteProviderId;
    private final GrpcHsmClient client;
    private volatile ProviderDeviceInfo cachedDescriptor;

    public GrpcCryptoProviderAdapter(String providerId, String remoteProviderId, GrpcHsmClient client, ProviderDescriptor initial) {
        this.providerId = providerId;
        this.remoteProviderId = remoteProviderId;
        this.client = client;
        this.cachedDescriptor = toInfo(providerId, initial);
    }

    @Override
    public String providerId() {
        return providerId;
    }

    @Override
    public String providerType() {
        return "PKCS11J_GRPC";
    }

    @Override
    public ProviderDeviceInfo getDeviceInfo() {
        try {
            ListProvidersResponse resp = client.listProviders();
            for (ProviderDescriptor pd : resp.getProvidersList()) {
                if (remoteProviderId.equals(pd.getProviderId())) {
                    ProviderDeviceInfo updated = toInfo(providerId, pd);
                    this.cachedDescriptor = updated;
                    return updated;
                }
            }
        } catch (Exception e) {
            log.warn("Failed to refresh provider '{}' info via gRPC: {}", providerId, e.getMessage());
            ProviderDeviceInfo prev = this.cachedDescriptor;
            if (prev != null) {
                return new ProviderDeviceInfo(
                        prev.providerId(), prev.providerType(), prev.libraryPath(), prev.tokenLabel(),
                        prev.slotId(), false, "UNREACHABLE: " + e.getMessage(), prev.keyLabels(), prev.keyAlgorithms());
            }
        }
        return cachedDescriptor;
    }

    @Override
    public List<String> listKeyLabels() {
        ListKeysResponse resp = client.listKeys(remoteProviderId);
        return resp.getKeysList().stream()
                .map(KeyDescriptor::getKeyLabel)
                .distinct()
                .toList();
    }

    @Override
    public Map<String, String> getKeyAlgorithms() {
        ListKeysResponse resp = client.listKeys(remoteProviderId);
        Map<String, String> map = new LinkedHashMap<>();
        for (KeyDescriptor k : resp.getKeysList()) {
            map.put(k.getKeyLabel(), k.getKeyAlgorithm());
        }
        return map;
    }

    @Override
    public String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
        GenerateCsrRpcResponse resp = client.generateCsr(
                remoteProviderId, keyLabel, subjectDn, keyAlgorithm, keySize, reuseExistingKey);
        return resp.getCsrPem();
    }

    @Override
    public void importCertificate(String keyLabel, X509CertificateHolder certificate) {
        try {
            client.importCertificate(remoteProviderId, keyLabel, certificate.getEncoded());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode certificate DER for remote HSM import", e);
        }
    }

    @Override
    public byte[] sign(String keyLabel, String signatureAlgorithm, byte[] data) {
        return client.sign(remoteProviderId, keyLabel, signatureAlgorithm, data);
    }

    @Override
    public ContentSigner createContentSigner(String keyLabel, String signatureAlgorithm) {
        AlgorithmIdentifier algId = ALG_FINDER.find(signatureAlgorithm);
        return new ContentSigner() {
            private final ByteArrayOutputStream buffer = new ByteArrayOutputStream(2048);

            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return algId;
            }

            @Override
            public OutputStream getOutputStream() {
                return buffer;
            }

            @Override
            public byte[] getSignature() {
                return sign(keyLabel, signatureAlgorithm, buffer.toByteArray());
            }
        };
    }

    private static ProviderDeviceInfo toInfo(String localProviderId, ProviderDescriptor pd) {
        if (pd == null) {
            return new ProviderDeviceInfo(localProviderId, "PKCS11J_GRPC", "grpc", "", 0L, false, "Unknown", List.of(), Map.of());
        }
        List<String> labels = pd.getKeysList().stream().map(KeyDescriptor::getKeyLabel).distinct().toList();
        Map<String, String> algs = new LinkedHashMap<>();
        for (KeyDescriptor k : pd.getKeysList()) {
            algs.put(k.getKeyLabel(), k.getKeyAlgorithm());
        }
        return new ProviderDeviceInfo(
                localProviderId,
                pd.getProviderType().isBlank() ? "PKCS11J_GRPC" : pd.getProviderType(),
                pd.getLibraryPath(),
                pd.getTokenLabel(),
                pd.getSlotId(),
                pd.getHealthy(),
                pd.getStatusMessage(),
                labels,
                algs
        );
    }
}

