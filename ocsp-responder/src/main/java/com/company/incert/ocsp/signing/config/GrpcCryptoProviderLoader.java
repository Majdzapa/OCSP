package com.company.incert.ocsp.signing.config;

import com.company.incert.hsm.grpc.v1.ListProvidersResponse;
import com.company.incert.hsm.grpc.v1.ProviderDescriptor;
import com.company.incert.ocsp.signing.provider.GrpcCryptoProviderAdapter;
import com.company.incert.ocsp.signing.provider.GrpcHsmClient;
import com.company.incert.ocsp.signing.provider.PkcsProviders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Loads remote PKCS11J providers exposed by one or more {@code hsm-signer} gRPC daemons
 * when {@code hsm.mode=GRPC}.
 */
@Slf4j
@Component
@Order(10)
@RequiredArgsConstructor
public class GrpcCryptoProviderLoader implements CryptoProviderLoader {

    private final ResourceLoader resourceLoader;

    @Override
    public boolean supports(String mode) {
        return "GRPC".equalsIgnoreCase(mode);
    }

    @Override
    public void loadInto(PkcsProviders registry, HsmProperties hsm) {
        List<HsmProperties.GrpcClientProperties> targets = collectEndpoints(hsm);
        if (targets.isEmpty()) {
            throw new IllegalStateException("hsm.mode=GRPC requires hsm.grpc.host/port or hsm.grpc.endpoints");
        }

        String suggestedDefault = null;
        for (HsmProperties.GrpcClientProperties endpoint : targets) {
            GrpcHsmClient client = new GrpcHsmClient(
                    endpoint.getHost(),
                    endpoint.getPort(),
                    endpoint.getTimeoutSeconds(),
                    endpoint.isTlsEnabled(),
                    endpoint.getKeyStore(),
                    endpoint.getKeyStorePassword(),
                    endpoint.getTrustStore(),
                    endpoint.getTrustStorePassword(),
                    resourceLoader);
            registry.trackManagedClient(client);

            ListProvidersResponse resp = fetchProvidersWithRetry(client, endpoint.getHost(), endpoint.getPort());
            String prefix = (endpoint.getIdPrefix() != null && !endpoint.getIdPrefix().isBlank())
                    ? endpoint.getIdPrefix().trim() + "-"
                    : "";

            for (ProviderDescriptor pd : resp.getProvidersList()) {
                String localId = prefix + pd.getProviderId();
                registry.register(new GrpcCryptoProviderAdapter(localId, pd.getProviderId(), client, pd));
                log.info("Discovered remote PKCS11J device '{}' on gRPC {}:{} (token='{}', slotId={}, healthy={})",
                        localId, endpoint.getHost(), endpoint.getPort(), pd.getTokenLabel(), pd.getSlotId(), pd.getHealthy());
            }

            if (suggestedDefault == null && !resp.getDefaultProviderId().isBlank()) {
                suggestedDefault = prefix + resp.getDefaultProviderId();
            }
        }

        if (registry.listProviderIds().isEmpty()) {
            throw new IllegalStateException("No PKCS11J signing devices discovered over gRPC");
        }
        if (suggestedDefault != null && registry.listProviderIds().contains(suggestedDefault)) {
            registry.setDefaultProviderId(suggestedDefault);
        }
    }

    private static List<HsmProperties.GrpcClientProperties> collectEndpoints(HsmProperties hsm) {
        List<HsmProperties.GrpcClientProperties> targets = new ArrayList<>();
        HsmProperties.GrpcClientProperties primary = hsm.getGrpc();
        if (primary != null && primary.getHost() != null && !primary.getHost().isBlank()) {
            targets.add(primary);
        }
        if (primary != null && primary.getEndpoints() != null) {
            targets.addAll(primary.getEndpoints());
        }
        return targets;
    }

    private ListProvidersResponse fetchProvidersWithRetry(GrpcHsmClient client, String host, int port) {
        int maxAttempts = 5;
        RuntimeException lastError = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return client.listProviders();
            } catch (RuntimeException e) {
                lastError = e;
                log.warn("Waiting for hsm-signer gRPC {}:{} (attempt {}/{}): {}",
                        host, port, attempt, maxAttempts, e.getMessage());
                if (attempt < maxAttempts) {
                    try {
                        Thread.sleep(2000L);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("Interrupted connecting to hsm-signer gRPC", ie);
                    }
                }
            }
        }
        throw new IllegalStateException("Unable to reach hsm-signer gRPC at " + host + ":" + port
                + " after " + maxAttempts + " attempts", lastError);
    }
}

