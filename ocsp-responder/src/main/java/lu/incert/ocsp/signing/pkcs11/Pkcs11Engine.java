package lu.incert.ocsp.signing.pkcs11;

import lu.incert.ocsp.signing.pkcs11.crypto.KeyPairStrategies;
import lu.incert.ocsp.signing.pkcs11.crypto.SignatureStrategies;
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

    /**
     * Initializes a PKCS#11 token (or creates a new virtual slot on SoftHSM2 when {@code slotId == null})
     * via {@code C_InitToken} + SO {@code C_Login} + {@code C_InitPIN}. Both PINs are wiped immediately.
     */
    public synchronized TokenInfo initToken(
            String libraryPath,
            String libraryWrapperPath,
            Long slotId,
            String tokenLabel,
            char[] soPin,
            char[] userPin) {
        try {
            if (tokenLabel == null || tokenLabel.isBlank()) {
                throw new IllegalArgumentException("tokenLabel must not be blank");
            }
            String cleanLabel = tokenLabel.trim();
            if (cleanLabel.length() > 32) {
                throw new IllegalArgumentException("tokenLabel must be at most 32 characters (PKCS#11 limit)");
            }
            if (soPin == null || soPin.length == 0) {
                throw new IllegalArgumentException("Security Officer (SO) PIN is required");
            }
            if (userPin == null || userPin.length == 0) {
                throw new IllegalArgumentException("User PIN is required");
            }

            Pkcs11LibraryPort library = moduleRegistry.acquire(libraryPath, libraryWrapperPath);
            try {
                long targetSlotId = resolveTargetSlotForInit(library, libraryPath, slotId, cleanLabel);

                // Refuse to re-initialize a slot currently held open by an unlocked provider
                synchronized (providersById) {
                    for (Pkcs11Provider active : providersById.values()) {
                        if (active.getSlotId() == targetSlotId) {
                            throw new IllegalStateException("Slot " + targetSlotId
                                    + " is currently ACTIVE on device '" + active.getProviderId()
                                    + "'. Lock the device before re-initializing its token.");
                        }
                    }
                }

                // Step 1: C_InitToken (initializes token & creates new Vslot on SoftHSM2)
                library.cInitToken(targetSlotId, soPin, cleanLabel);

                // Step 2: Re-query slot list (SoftHSM2 reassigns a new slotId after C_InitToken)
                TokenInfo initializedToken = findInitializedToken(library, targetSlotId, cleanLabel);

                // Step 3: Open RW session as SO -> C_InitPIN(userPin) -> C_Logout -> C_CloseSession
                long session = library.cOpenSession(
                        initializedToken.slotId(),
                        Pkcs11Constants.CKF_SERIAL_SESSION | Pkcs11Constants.CKF_RW_SESSION);
                try {
                    long rv = library.cLogin(session, Pkcs11Constants.CKU_SO, soPin);
                    if (rv != Pkcs11Constants.CKR_OK && rv != Pkcs11Constants.CKR_USER_ALREADY_LOGGED_IN) {
                        throw new Pkcs11Exception("C_Login(CKU_SO)", rv);
                    }
                    try {
                        library.cInitPin(session, userPin);
                    } finally {
                        try {
                            library.cLogout(session);
                        } catch (Exception ignored) {}
                    }
                } finally {
                    try {
                        library.cCloseSession(session);
                    } catch (Exception ignored) {}
                }

                TokenInfo finalInfo = library.cGetTokenInfo(initializedToken.slotId());
                log.info("Initialized PKCS#11 token '{}' on slot {} (serial='{}', library='{}')",
                        finalInfo.label(), finalInfo.slotId(), finalInfo.serialNumber(), libraryPath);
                return finalInfo;
            } finally {
                moduleRegistry.release(libraryPath);
            }
        } finally {
            if (soPin != null) {
                java.util.Arrays.fill(soPin, '\0');
            }
            if (userPin != null) {
                java.util.Arrays.fill(userPin, '\0');
            }
        }
    }

    private static long resolveTargetSlotForInit(
            Pkcs11LibraryPort library,
            String libraryPath,
            Long requestedSlotId,
            String cleanLabel) {
        long[] slotIds = library.cGetSlotList(true);
        if (slotIds == null || slotIds.length == 0) {
            throw new IllegalStateException("No PKCS#11 slots with tokens present for library '" + libraryPath + "'");
        }
        // Prevent duplicate token labels on another slot when creating a new Vslot
        for (long s : slotIds) {
            try {
                TokenInfo info = library.cGetTokenInfo(s);
                boolean initialized = (info.flags() & Pkcs11Constants.CKF_TOKEN_INITIALIZED) != 0L;
                if (initialized && cleanLabel.equals(info.label().trim())
                        && (requestedSlotId == null || requestedSlotId != s)) {
                    throw new IllegalArgumentException(
                            "A token with label '" + cleanLabel + "' already exists on slot " + s
                                    + ". Choose a unique token label or select slot " + s + " to re-initialize it.");
                }
            } catch (Pkcs11Exception ignored) {}
        }

        if (requestedSlotId != null) {
            for (long s : slotIds) {
                if (s == requestedSlotId) {
                    return requestedSlotId;
                }
            }
            throw new IllegalArgumentException("Requested PKCS#11 slot " + requestedSlotId
                    + " not found in library '" + libraryPath + "'");
        }

        // Auto-select first uninitialized free slot (creates a brand-new Vslot on SoftHSM2)
        for (long s : slotIds) {
            try {
                TokenInfo info = library.cGetTokenInfo(s);
                boolean initialized = (info.flags() & Pkcs11Constants.CKF_TOKEN_INITIALIZED) != 0L;
                if (!initialized) {
                    return s;
                }
            } catch (Pkcs11Exception e) {
                if (e.getErrorCode() != Pkcs11Constants.CKR_TOKEN_NOT_PRESENT) {
                    return s;
                }
            }
        }
        throw new IllegalStateException(
                "No free uninitialized PKCS#11 slot available on '" + libraryPath
                        + "'. Select an existing slot ID to re-initialize or provision a new slot on the HSM.");
    }

    private static TokenInfo findInitializedToken(Pkcs11LibraryPort library, long originalSlotId, String cleanLabel) {
        long[] updatedSlots = library.cGetSlotList(true);
        if (updatedSlots != null) {
            for (long s : updatedSlots) {
                try {
                    TokenInfo info = library.cGetTokenInfo(s);
                    boolean initialized = (info.flags() & Pkcs11Constants.CKF_TOKEN_INITIALIZED) != 0L;
                    if (initialized && cleanLabel.equals(info.label().trim())) {
                        return info;
                    }
                } catch (Pkcs11Exception ignored) {}
            }
        }
        return library.cGetTokenInfo(originalSlotId);
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

