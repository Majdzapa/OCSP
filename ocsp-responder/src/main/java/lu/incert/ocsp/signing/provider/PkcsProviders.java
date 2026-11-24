package lu.incert.ocsp.signing.provider;

import lu.incert.ocsp.signing.port.ActivatableCryptoProvider;
import lu.incert.ocsp.signing.port.CryptoProviderPort;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Multi-device runtime registry of {@link CryptoProviderPort} implementations inside {@code ocsp-responder}.
 * Supports dynamic registration, replacement, unregistration, and Pattern 2 runtime activation/deactivation.
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

    public synchronized void replace(CryptoProviderPort port) {
        Objects.requireNonNull(port, "port must not be null");
        String id = port.providerId().trim();
        CryptoProviderPort previous = providersById.put(id, port);
        if (previous != null && previous != port) {
            safeClose(previous, id);
        }
        if (defaultProviderId == null) {
            defaultProviderId = id;
        }
        log.info("Updated runtime registration for signing provider '{}' (type={})", id, port.providerType());
    }

    public synchronized boolean unregister(String providerId) {
        if (providerId == null || providerId.isBlank()) {
            return false;
        }
        String clean = providerId.trim();
        CryptoProviderPort removed = providersById.remove(clean);
        if (removed == null) {
            return false;
        }
        if (clean.equals(defaultProviderId)) {
            defaultProviderId = providersById.keySet().stream().findFirst().orElse(null);
        }
        safeClose(removed, clean);
        log.info("Unregistered signing provider '{}'", clean);
        return true;
    }

    public boolean hasProvider(String providerId) {
        return providerId != null && !providerId.isBlank() && providersById.containsKey(providerId.trim());
    }

    public void activate(String providerId, char[] pin) {
        try {
            CryptoProviderPort port = getProvider(providerId);
            if (!(port instanceof ActivatableCryptoProvider activatable)) {
                throw new UnsupportedOperationException(
                        "Device '" + port.providerId() + "' (" + port.providerType() + ") does not support runtime activation");
            }
            activatable.activate(pin);
        } finally {
            if (pin != null) {
                Arrays.fill(pin, '\0');
            }
        }
    }

    public void deactivate(String providerId) {
        CryptoProviderPort port = getProvider(providerId);
        if (!(port instanceof ActivatableCryptoProvider activatable)) {
            throw new UnsupportedOperationException(
                    "Device '" + port.providerId() + "' (" + port.providerType() + ") does not support runtime deactivation");
        }
        activatable.deactivate();
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
            safeClose(p, p.providerId());
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

    private static void safeClose(CryptoProviderPort port, String id) {
        try {
            port.close();
        } catch (Exception e) {
            log.warn("Error closing provider '{}': {}", id, e.getMessage());
        }
    }
}
