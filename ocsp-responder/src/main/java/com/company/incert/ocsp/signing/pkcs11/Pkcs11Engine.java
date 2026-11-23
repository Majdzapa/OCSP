package com.company.incert.ocsp.signing.pkcs11;

import com.company.incert.ocsp.signing.pkcs11.crypto.KeyPairStrategies;
import com.company.incert.ocsp.signing.pkcs11.crypto.SignatureStrategies;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Multi-device PKCS#11 engine delegating shared-library reference counting ({@code C_Initialize}/{@code C_Finalize})
 * to {@link Pkcs11ModuleRegistry}, defaulting to Maven Central {@link XiPkiPkcs11Library}.
 */
public final class Pkcs11Engine implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11Engine.class);

    private final Pkcs11ModuleRegistry moduleRegistry;
    private final KeyPairStrategies keyPairStrategies;
    private final SignatureStrategies signatureStrategies;
    private final Map<String, Pkcs11Provider> providersById = Collections.synchronizedMap(new LinkedHashMap<>());
    private volatile String defaultProviderId;

    public Pkcs11Engine() {
        this((BiFunction<String, String, Pkcs11LibraryPort>) XiPkiPkcs11Library::new,
                new KeyPairStrategies(), new SignatureStrategies());
    }

    public Pkcs11Engine(Function<String, Pkcs11LibraryPort> libraryFactory) {
        this((libPath, wrapperPath) -> Objects.requireNonNull(libraryFactory, "libraryFactory must not be null")
                .apply(libPath), new KeyPairStrategies(), new SignatureStrategies());
    }

    public Pkcs11Engine(BiFunction<String, String, Pkcs11LibraryPort> libraryFactory) {
        this(libraryFactory, new KeyPairStrategies(), new SignatureStrategies());
    }

    public Pkcs11Engine(
            BiFunction<String, String, Pkcs11LibraryPort> libraryFactory,
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
        return register(config, null);
    }

    public synchronized Pkcs11Provider register(Pkcs11ProviderConfig config, Runnable onLoggedOut) {
        Objects.requireNonNull(config, "config must not be null");
        String id = config.providerId().trim();
        if (providersById.containsKey(id)) {
            config.wipePin();
            throw new IllegalArgumentException("PKCS#11 provider already registered with id '" + id + "'");
        }

        Pkcs11LibraryPort library = moduleRegistry.acquire(config.libraryPath(), config.libraryWrapperPath());
        Pkcs11Provider provider;
        try {
            provider = new Pkcs11Provider(
                    config,
                    library,
                    keyPairStrategies,
                    signatureStrategies,
                    () -> moduleRegistry.release(config.libraryPath()),
                    onLoggedOut);
        } catch (RuntimeException e) {
            config.wipePin();
            moduleRegistry.release(config.libraryPath());
            throw e;
        }

        providersById.put(id, provider);
        if (defaultProviderId == null) {
            defaultProviderId = id;
        }
        return provider;
    }

    public synchronized boolean unregister(String providerId) {
        if (providerId == null || providerId.isBlank()) {
            return false;
        }
        String clean = providerId.trim();
        Pkcs11Provider removed = providersById.remove(clean);
        if (removed == null) {
            return false;
        }
        if (clean.equals(defaultProviderId)) {
            defaultProviderId = providersById.keySet().stream().findFirst().orElse(null);
        }
        try {
            removed.close();
        } catch (Exception e) {
            log.warn("Error closing unregistered PKCS#11 provider '{}': {}", clean, e.getMessage());
        }
        return true;
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

    public Collection<String> listProviderIds() {
        synchronized (providersById) {
            return List.copyOf(providersById.keySet());
        }
    }

    public int loadedModuleCount() {
        return moduleRegistry.loadedModuleCount();
    }

    /**
     * Discovers token-present PKCS#11 slots ({@code C_GetSlotList(true)} + {@code C_GetTokenInfo})
     * without requiring a user PIN or closing modules already held by active devices.
     */
    public synchronized List<TokenInfo> discoverSlots(String libraryPath, String libraryWrapperPath) {
        Pkcs11LibraryPort library = moduleRegistry.acquire(libraryPath, libraryWrapperPath);
        try {
            long[] slotIds = library.cGetSlotList(true);
            if (slotIds == null || slotIds.length == 0) {
                return List.of();
            }
            List<TokenInfo> slots = new ArrayList<>(slotIds.length);
            for (long slotId : slotIds) {
                try {
                    slots.add(library.cGetTokenInfo(slotId));
                } catch (Pkcs11Exception e) {
                    log.debug("Failed reading C_GetTokenInfo for slot {} on '{}': {}",
                            slotId, libraryPath, e.getMessage());
                    if (e.getErrorCode() != Pkcs11Constants.CKR_TOKEN_NOT_PRESENT) {
                        slots.add(new TokenInfo(slotId, "", "", "", "", 0L));
                    }
                }
            }
            return Collections.unmodifiableList(slots);
        } finally {
            moduleRegistry.release(libraryPath);
        }
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
                log.warn("Error closing provider '{}': {}", p.getProviderId(), e.getMessage());
            }
        }
    }
}

