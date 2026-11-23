package com.company.incert.pkcs11j.provider;

import com.company.incert.pkcs11j.crypto.KeyPairStrategies;
import com.company.incert.pkcs11j.crypto.SignatureStrategies;
import com.company.incert.pkcs11j.nativebridge.JniPkcs11Library;
import com.company.incert.pkcs11j.port.Pkcs11LibraryPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Multi-device PKCS#11 registry delegating shared library ref-counting and {@code C_Initialize}/{@code C_Finalize}
 * lifecycle to {@link Pkcs11ModuleRegistry}.
 */
public final class PkcsProviders implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(PkcsProviders.class);

    private final Pkcs11ModuleRegistry moduleRegistry;
    private final KeyPairStrategies keyPairStrategies;
    private final SignatureStrategies signatureStrategies;
    private final Map<String, Pkcs11Provider> providersById = Collections.synchronizedMap(new LinkedHashMap<>());
    private volatile String defaultProviderId;

    public PkcsProviders() {
        this(JniPkcs11Library::new, new KeyPairStrategies(), new SignatureStrategies());
    }

    public PkcsProviders(Function<String, Pkcs11LibraryPort> libraryFactory) {
        this(libraryFactory, new KeyPairStrategies(), new SignatureStrategies());
    }

    public PkcsProviders(
            Function<String, Pkcs11LibraryPort> libraryFactory,
            KeyPairStrategies keyPairStrategies,
            SignatureStrategies signatureStrategies) {
        this.moduleRegistry = new Pkcs11ModuleRegistry(libraryFactory);
        this.keyPairStrategies = Objects.requireNonNull(keyPairStrategies, "keyPairStrategies must not be null");
        this.signatureStrategies = Objects.requireNonNull(signatureStrategies, "signatureStrategies must not be null");
    }

    public KeyPairStrategies getKeyPairStrategies() {
        return keyPairStrategies;
    }

    public SignatureStrategies getSignatureStrategies() {
        return signatureStrategies;
    }

    public synchronized Pkcs11Provider register(Pkcs11ProviderConfig config) {
        Objects.requireNonNull(config, "config must not be null");
        String id = config.providerId().trim();
        if (providersById.containsKey(id)) {
            throw new IllegalArgumentException("PKCS#11 provider already registered with id '" + id + "'");
        }

        Pkcs11LibraryPort library = moduleRegistry.acquire(config.libraryPath());
        Pkcs11Provider provider;
        try {
            provider = new Pkcs11Provider(
                    config,
                    library,
                    keyPairStrategies,
                    signatureStrategies,
                    () -> moduleRegistry.release(config.libraryPath()));
        } catch (RuntimeException e) {
            moduleRegistry.release(config.libraryPath());
            throw e;
        }

        providersById.put(id, provider);
        if (defaultProviderId == null) {
            defaultProviderId = id;
        }
        return provider;
    }

    public synchronized void setDefaultProviderId(String providerId) {
        if (providerId == null || providerId.isBlank()) {
            return;
        }
        String clean = providerId.trim();
        if (!providersById.containsKey(clean)) {
            throw new IllegalArgumentException("Unknown default PKCS#11 providerId: '" + clean + "'");
        }
        this.defaultProviderId = clean;
    }

    public String getDefaultProviderId() {
        return defaultProviderId;
    }

    public Pkcs11Provider getProvider(String providerId) {
        String resolved = (providerId == null || providerId.isBlank() || "default".equalsIgnoreCase(providerId.trim()))
                ? defaultProviderId
                : providerId.trim();
        if (resolved == null) {
            throw new IllegalStateException("No PKCS#11 providers are registered");
        }
        Pkcs11Provider p = providersById.get(resolved);
        if (p == null) {
            throw new IllegalArgumentException("Unknown PKCS#11 provider '" + resolved
                    + "'. Registered: " + providersById.keySet());
        }
        return p;
    }

    public Pkcs11Provider getDefaultProvider() {
        return getProvider(null);
    }

    public List<Pkcs11Provider> listProviders() {
        synchronized (providersById) {
            return new ArrayList<>(providersById.values());
        }
    }

    public Collection<String> listProviderIds() {
        synchronized (providersById) {
            return List.copyOf(providersById.keySet());
        }
    }

    public int loadedModuleCount() {
        return moduleRegistry.loadedModuleCount();
    }

    @Override
    public synchronized void close() {
        List<Pkcs11Provider> snapshot;
        synchronized (providersById) {
            snapshot = new ArrayList<>(providersById.values());
            providersById.clear();
            defaultProviderId = null;
        }
        for (Pkcs11Provider p : snapshot) {
            try {
                p.close();
            } catch (Exception e) {
                log.warn("Error closing PKCS#11 provider '{}': {}", p.getProviderId(), e.getMessage());
            }
        }
    }
}
