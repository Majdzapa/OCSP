package com.company.incert.ocsp.signing.provider;

import com.company.incert.hsm.grpc.v1.GenerateCsrRpcResponse;
import com.company.incert.hsm.grpc.v1.KeyDescriptor;
import com.company.incert.hsm.grpc.v1.ListKeysResponse;
import com.company.incert.hsm.grpc.v1.ProviderDescriptor;
import com.company.incert.ocsp.signing.port.CryptoProviderPort;
import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@link CryptoProviderPort} adapter delegating cryptographic operations for one remote HSM provider
 * over persistent gRPC to {@code hsm-signer}.
 */
@Slf4j
public class GrpcCryptoProviderAdapter implements CryptoProviderPort {

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
        ProviderDeviceInfo base = this.cachedDescriptor;
        try {
            ListKeysResponse resp = client.listKeys(remoteProviderId);
            List<String> labels = extractLabels(resp.getKeysList());
            Map<String, String> algs = extractAlgorithms(resp.getKeysList());
            ProviderDeviceInfo updated = new ProviderDeviceInfo(
                    base.providerId(),
                    base.providerType(),
                    base.libraryPath(),
                    base.tokenLabel(),
                    base.slotId(),
                    true,
                    "UP (gRPC " + labels.size() + " key(s))",
                    labels,
                    algs
            );
            this.cachedDescriptor = updated;
            return updated;
        } catch (Exception e) {
            log.warn("Failed to refresh provider '{}' keys via gRPC: {}", providerId, e.getMessage());
            return new ProviderDeviceInfo(
                    base.providerId(), base.providerType(), base.libraryPath(), base.tokenLabel(),
                    base.slotId(), false, "UNREACHABLE: " + e.getMessage(), base.keyLabels(), base.keyAlgorithms());
        }
    }

    @Override
    public List<String> listKeyLabels() {
        return extractLabels(client.listKeys(remoteProviderId).getKeysList());
    }

    @Override
    public Map<String, String> getKeyAlgorithms() {
        return extractAlgorithms(client.listKeys(remoteProviderId).getKeysList());
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

    private static List<String> extractLabels(List<KeyDescriptor> keys) {
        return keys.stream().map(KeyDescriptor::getKeyLabel).distinct().toList();
    }

    private static Map<String, String> extractAlgorithms(List<KeyDescriptor> keys) {
        Map<String, String> map = new LinkedHashMap<>();
        for (KeyDescriptor k : keys) {
            map.put(k.getKeyLabel(), k.getKeyAlgorithm());
        }
        return map;
    }

    private static ProviderDeviceInfo toInfo(String localProviderId, ProviderDescriptor pd) {
        if (pd == null) {
            return new ProviderDeviceInfo(localProviderId, "PKCS11J_GRPC", "grpc", "", 0L, false, "Unknown", List.of(), Map.of());
        }
        return new ProviderDeviceInfo(
                localProviderId,
                pd.getProviderType().isBlank() ? "PKCS11J_GRPC" : pd.getProviderType(),
                pd.getLibraryPath(),
                pd.getTokenLabel(),
                pd.getSlotId(),
                pd.getHealthy(),
                pd.getStatusMessage(),
                extractLabels(pd.getKeysList()),
                extractAlgorithms(pd.getKeysList())
        );
    }
}
