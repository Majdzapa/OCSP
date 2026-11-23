package com.company.incert.ocsp.signing.provider;

import com.company.incert.ocsp.signing.port.CryptoProviderPort;
import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Multi-device registry of {@link CryptoProviderPort} implementations inside {@code ocsp-responder}.
 * Allows multiple HSM tokens, remote gRPC {@code PKCS11J} endpoints, and local PKCS#11 devices to operate
 * simultaneously and routes CSR generation, key lookup, certificate import, and OCSP response signing per {@code providerId}.
 */
@Slf4j
public class PkcsProviders implements AutoCloseable {

    private final Map<String, CryptoProviderPort> providersById = Collections.synchronizedMap(new LinkedHashMap<>());
    private final List<AutoCloseable> managedClients = new CopyOnWriteArrayList<>();
    private volatile String defaultProviderId;

    public synchronized void register(CryptoProviderPort port) {
        Objects.requireNonNull(port, "port must not be null");
        String id = port.providerId().trim();
        if (providersById.containsKey(id)) {
            throw new IllegalArgumentException("Signing provider already registered with id '" + id + "'");
        }
        providersById.put(id, port);
        if (defaultProviderId == null) {
            defaultProviderId = id;
        }
        log.info("Registered signing provider '{}' (type={})", id, port.providerType());
    }

    public void trackManagedClient(AutoCloseable client) {
        if (client != null) {
            managedClients.add(client);
        }
    }

    public synchronized void setDefaultProviderId(String providerId) {
        if (providerId == null || providerId.isBlank()) {
            return;
        }
        String clean = providerId.trim();
        if (!providersById.containsKey(clean)) {
            throw new IllegalArgumentException("Unknown default providerId: '" + clean
                    + "'. Registered: " + providersById.keySet());
        }
        this.defaultProviderId = clean;
    }

    public String getDefaultProviderId() {
        return defaultProviderId;
    }

    public CryptoProviderPort getProvider(String providerId) {
        String resolved = (providerId == null || providerId.isBlank() || "default".equalsIgnoreCase(providerId.trim()))
                ? defaultProviderId
                : providerId.trim();
        if (resolved == null) {
            throw new IllegalStateException("No signing providers are registered in PkcsProviders");
        }
        CryptoProviderPort port = providersById.get(resolved);
        if (port == null) {
            throw new IllegalArgumentException("Unknown signing provider '" + resolved
                    + "'. Available providers: " + providersById.keySet());
        }
        return port;
    }

    public CryptoProviderPort getDefaultProvider() {
        return getProvider(null);
    }

    public List<ProviderDeviceInfo> listProviders() {
        List<CryptoProviderPort> snapshot;
        synchronized (providersById) {
            snapshot = new ArrayList<>(providersById.values());
        }
        return snapshot.stream()
                .map(CryptoProviderPort::getDeviceInfo)
                .toList();
    }

    public List<String> listProviderIds() {
        synchronized (providersById) {
            return List.copyOf(providersById.keySet());
        }
    }

    @Override
    public synchronized void close() {
        List<CryptoProviderPort> snapshot;
        synchronized (providersById) {
            snapshot = new ArrayList<>(providersById.values());
            providersById.clear();
            defaultProviderId = null;
        }
        for (CryptoProviderPort p : snapshot) {
            try {
                p.close();
            } catch (Exception e) {
                log.warn("Error closing provider '{}': {}", p.providerId(), e.getMessage());
            }
        }
        for (AutoCloseable client : managedClients) {
            try {
                client.close();
            } catch (Exception e) {
                log.warn("Error closing managed HSM client: {}", e.getMessage());
            }
        }
        managedClients.clear();
    }
}

