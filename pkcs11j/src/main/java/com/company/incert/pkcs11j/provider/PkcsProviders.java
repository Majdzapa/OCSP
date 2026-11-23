package com.company.incert.pkcs11j.provider;

import com.company.incert.pkcs11j.Pkcs11Constants;
import com.company.incert.pkcs11j.Pkcs11Exception;
import com.company.incert.pkcs11j.nativebridge.JniPkcs11Library;
import com.company.incert.pkcs11j.port.Pkcs11LibraryPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Multi-device PKCS#11 registry that initializes each native shared library ({@code C_Initialize})
 * once per process, shares the initialized {@link Pkcs11LibraryPort} across multiple slots/tokens,
 * and finalizes ({@code C_Finalize}) cleanly via reference counting on shutdown.
 */
public final class PkcsProviders implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(PkcsProviders.class);

    private final Function<String, Pkcs11LibraryPort> libraryFactory;
    private final Map<String, LoadedModule> modulesByPath = new ConcurrentHashMap<>();
    private final Map<String, Pkcs11Provider> providersById = Collections.synchronizedMap(new LinkedHashMap<>());
    private volatile String defaultProviderId;

    public PkcsProviders() {
        this(JniPkcs11Library::new);
    }

    public PkcsProviders(Function<String, Pkcs11LibraryPort> libraryFactory) {
        this.libraryFactory = Objects.requireNonNull(libraryFactory, "libraryFactory must not be null");
    }

    public synchronized Pkcs11Provider register(Pkcs11ProviderConfig config) {
        Objects.requireNonNull(config, "config must not be null");
        String id = config.providerId().trim();
        if (providersById.containsKey(id)) {
            throw new IllegalArgumentException("PKCS#11 provider already registered with id '" + id + "'");
        }

        String canonicalLibPath = canonicalizePath(config.libraryPath());
        Pkcs11LibraryPort library = acquireModule(canonicalLibPath);

        Pkcs11Provider provider;
        try {
            provider = new Pkcs11Provider(config, library, () -> releaseModule(canonicalLibPath));
        } catch (RuntimeException e) {
            releaseModule(canonicalLibPath);
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
        return modulesByPath.size();
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

    private Pkcs11LibraryPort acquireModule(String canonicalPath) {
        LoadedModule entry = modulesByPath.compute(canonicalPath, (path, existing) -> {
            if (existing != null) {
                existing.refCount++;
                return existing;
            }
            Pkcs11LibraryPort port = libraryFactory.apply(path);
            try {
                long rv = port.cInitialize(Pkcs11Constants.CKF_OS_LOCKING_OK);
                if (rv != Pkcs11Constants.CKR_OK && rv != Pkcs11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                    throw new Pkcs11Exception("C_Initialize", rv);
                }
                log.info("Initialized PKCS#11 native module '{}' via C_Initialize (rv={})",
                        path, Pkcs11Constants.errorName(rv));
            } catch (RuntimeException e) {
                try {
                    port.close();
                } catch (Exception ignored) {}
                throw e;
            }
            return new LoadedModule(port, 1);
        });
        return entry.port;
    }

    private synchronized void releaseModule(String canonicalPath) {
        modulesByPath.computeIfPresent(canonicalPath, (path, existing) -> {
            existing.refCount--;
            if (existing.refCount <= 0) {
                try {
                    long rv = existing.port.cFinalize();
                    log.info("Finalized PKCS#11 native module '{}' via C_Finalize (rv={})",
                            path, Pkcs11Constants.errorName(rv));
                } catch (Exception e) {
                    log.warn("C_Finalize failed for module '{}': {}", path, e.getMessage());
                } finally {
                    try {
                        existing.port.close();
                    } catch (Exception ignored) {}
                }
                return null;
            }
            return existing;
        });
    }

    private static String canonicalizePath(String path) {
        return Path.of(path.trim()).toAbsolutePath().normalize().toString();
    }

    private static final class LoadedModule {
        final Pkcs11LibraryPort port;
        int refCount;

        LoadedModule(Pkcs11LibraryPort port, int refCount) {
            this.port = port;
            this.refCount = refCount;
        }
    }
}
