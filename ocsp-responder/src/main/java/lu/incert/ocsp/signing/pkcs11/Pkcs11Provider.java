package lu.incert.ocsp.signing.pkcs11;

import lu.incert.ocsp.signing.pkcs11.crypto.KeyPairStrategies;
import lu.incert.ocsp.signing.pkcs11.crypto.KeyPairStrategy;
import lu.incert.ocsp.signing.pkcs11.crypto.Pkcs11CsrGenerator;
import lu.incert.ocsp.signing.pkcs11.crypto.SignatureStrategies;
import lu.incert.ocsp.signing.pkcs11.crypto.SignatureStrategy;
import lu.incert.ocsp.signing.port.ProviderCapabilities;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Facade for a single unlocked PKCS#11 HSM slot/token, composing {@link Pkcs11SessionPool},
 * {@link Pkcs11ObjectStore}, and Open-Closed keygen/signing strategies.
 */
public final class Pkcs11Provider implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11Provider.class);

    private final Pkcs11ProviderConfig config;
    private final Pkcs11LibraryPort library;
    private final Pkcs11ObjectStore objectStore;
    private final KeyPairStrategies keyPairStrategies;
    private final SignatureStrategies signatureStrategies;
    private final long slotId;
    private final TokenInfo initialTokenInfo;
    private final Pkcs11SessionPool sessionPool;
    private final Runnable onCloseCallback;
    private volatile Map<Long, MechanismInfo> cachedMechanisms;

    Pkcs11Provider(
            Pkcs11ProviderConfig config,
            Pkcs11LibraryPort library,
            KeyPairStrategies keyPairStrategies,
            SignatureStrategies signatureStrategies,
            Runnable onCloseCallback,
            Runnable onLoggedOut) {
        this.config = config;
        this.library = library;
        this.objectStore = new Pkcs11ObjectStore(library);
        this.keyPairStrategies = keyPairStrategies;
        this.signatureStrategies = signatureStrategies;
        this.onCloseCallback = onCloseCallback;

        TokenResolution resolved = resolveSlot(library, config);
        this.slotId = resolved.slotId();
        this.initialTokenInfo = resolved.tokenInfo();
        char[] pinCopy = config.pinCopy();
        try {
            this.sessionPool = new Pkcs11SessionPool(library, slotId, pinCopy, config.poolSize(), onLoggedOut);
        } finally {
            Arrays.fill(pinCopy, '\0');
            config.wipePin();
        }
        log.info("Registered PKCS#11 provider '{}' (library={}, wrapper={}, token='{}', slotId={}, poolSize={})",
                config.providerId(), config.libraryPath(), config.libraryWrapperPath(),
                initialTokenInfo.label(), slotId, config.poolSize());
    }

    public String getProviderId() { return config.providerId(); }
    public String getLibraryPath() { return config.libraryPath(); }
    public String getLibraryWrapperPath() { return config.libraryWrapperPath(); }
    public String getTokenLabel() { return initialTokenInfo.label(); }
    public long getSlotId() { return slotId; }
    public TokenInfo getTokenInfo() { return library.cGetTokenInfo(slotId); }

    public List<KeyMetadata> listKeys() {
        return sessionPool.withSession(objectStore::listPrivateKeys);
    }

    public List<String> listKeyLabels() {
        return listKeys().stream().map(KeyMetadata::keyLabel).distinct().toList();
    }

    /**
     * Introspects the HSM slot's live PKCS#11 mechanisms ({@code C_GetMechanismList} + {@code C_GetMechanismInfo})
     * against all registered {@link KeyPairStrategy} and {@link SignatureStrategy} implementations.
     */
    public ProviderCapabilities getCapabilities() {
        Map<Long, MechanismInfo> mechs = getSlotMechanisms();

        List<ProviderCapabilities.KeyAlgorithmCapability> keyCaps = new ArrayList<>();
        for (KeyPairStrategy ks : keyPairStrategies.all()) {
            long genMech = ks.keyPairGenMechanism();
            String mechName = Pkcs11Constants.mechanismName(genMech);
            MechanismInfo info = mechs.get(genMech);
            if (info == null) {
                keyCaps.add(new ProviderCapabilities.KeyAlgorithmCapability(
                        ks.keyAlgorithmName(), false, List.of(), 0L, 0L, mechName,
                        "HSM slot " + slotId + " does not advertise " + mechName));
            } else if (!info.supportsKeyPairGen()) {
                keyCaps.add(new ProviderCapabilities.KeyAlgorithmCapability(
                        ks.keyAlgorithmName(), false, List.of(), info.minKeySize(), info.maxKeySize(), mechName,
                        mechName + " does not report CKF_GENERATE_KEY_PAIR on slot " + slotId));
            } else {
                List<Integer> allowedSizes = ks.supportedKeySizes().stream()
                        .filter(info::supportsKeySize)
                        .toList();
                boolean supported = !allowedSizes.isEmpty();
                String reason = supported
                        ? "Supported via " + mechName + " (" + allowedSizes + " bits)"
                        : "No supported key sizes fall within HSM range [" + info.minKeySize() + ".." + info.maxKeySize() + "]";
                keyCaps.add(new ProviderCapabilities.KeyAlgorithmCapability(
                        ks.keyAlgorithmName(), supported, allowedSizes, info.minKeySize(), info.maxKeySize(), mechName, reason));
            }
        }

        Map<String, List<String>> supportedByKeyType = new LinkedHashMap<>();
        List<ProviderCapabilities.SignatureAlgorithmCapability> sigCaps = new ArrayList<>();
        for (SignatureStrategy ss : signatureStrategies.all()) {
            for (String alg : ss.supportedAlgorithms()) {
                long reqMech = ss.requiredMechanism(alg, config.prehashInJvm());
                String mechName = Pkcs11Constants.mechanismName(reqMech);
                MechanismInfo info = mechs.get(reqMech);
                boolean supported = info != null && info.supportsSign();
                String reason;
                if (info == null) {
                    reason = "HSM slot " + slotId + " does not advertise " + mechName;
                } else if (!info.supportsSign()) {
                    reason = mechName + " does not report CKF_SIGN on slot " + slotId;
                } else {
                    reason = "Supported via " + mechName + (config.prehashInJvm() ? " (JVM pre-hash)" : "");
                    supportedByKeyType.computeIfAbsent(ss.keyType(), k -> new ArrayList<>()).add(alg);
                }
                sigCaps.add(new ProviderCapabilities.SignatureAlgorithmCapability(
                        alg, ss.keyType(), supported, mechName, reason));
            }
        }

        Map<String, List<String>> immutableByType = new LinkedHashMap<>();
        supportedByKeyType.forEach((k, v) -> immutableByType.put(k, List.copyOf(v)));

        return new ProviderCapabilities(
                config.providerId(),
                true,
                "Live PKCS#11 capabilities queried from slot " + slotId + " (" + mechs.size() + " mechanisms)",
                List.copyOf(keyCaps),
                Collections.unmodifiableMap(immutableByType),
                List.copyOf(sigCaps)
        );
    }

    /**
     * Validates a user-selected key algorithm / key size / existing key label and signature algorithm
     * against this HSM slot's live {@code C_GetMechanismList} and {@code C_GetMechanismInfo} before signing.
     */
    public ProviderCapabilities.AlgorithmValidationResult checkAlgorithmSupport(
            String keyLabel,
            String keyAlgorithm,
            Integer keySize,
            String signatureAlgorithm) {
        ProviderCapabilities caps = getCapabilities();
        Map<Long, MechanismInfo> mechs = getSlotMechanisms();

        String resolvedKeyAlg = null;
        Integer resolvedKeySize = keySize;

        // 1. Resolve key type from an existing HSM key if keyLabel is provided and present
        if (keyLabel != null && !keyLabel.isBlank()) {
            String cleanLabel = keyLabel.trim();
            Optional<KeyMetadata> existingKey = listKeys().stream()
                    .filter(k -> cleanLabel.equals(k.keyLabel()))
                    .findFirst();
            if (existingKey.isPresent()) {
                resolvedKeyAlg = existingKey.get().keyAlgorithm();
                if (resolvedKeySize == null) {
                    resolvedKeySize = existingKey.get().keySizeBits();
                }
            }
        }

        // 2. Validate requested keyAlgorithm / keySize when supplied (or when key does not exist yet)
        if (resolvedKeyAlg == null && keyAlgorithm != null && !keyAlgorithm.isBlank()) {
            KeyPairStrategy ks;
            try {
                ks = keyPairStrategies.resolve(keyAlgorithm);
            } catch (IllegalArgumentException e) {
                return new ProviderCapabilities.AlgorithmValidationResult(
                        false, config.providerId(), keyAlgorithm.trim(), resolvedKeySize, signatureAlgorithm,
                        null, List.of(), e.getMessage());
            }
            resolvedKeyAlg = ks.keyAlgorithmName();
            long genMech = ks.keyPairGenMechanism();
            String genMechName = Pkcs11Constants.mechanismName(genMech);
            MechanismInfo genInfo = mechs.get(genMech);
            if (genInfo == null || !genInfo.supportsKeyPairGen()) {
                return new ProviderCapabilities.AlgorithmValidationResult(
                        false, config.providerId(), resolvedKeyAlg, resolvedKeySize, signatureAlgorithm,
                        genMechName, List.of(),
                        "Key algorithm '" + resolvedKeyAlg + "' is NOT supported on HSM device '"
                                + config.providerId() + "' (missing " + genMechName + " on slot " + slotId + ")");
            }
            if (resolvedKeySize != null) {
                if (!ks.supportedKeySizes().contains(resolvedKeySize) || !genInfo.supportsKeySize(resolvedKeySize)) {
                    List<Integer> allowed = ks.supportedKeySizes().stream().filter(genInfo::supportsKeySize).toList();
                    return new ProviderCapabilities.AlgorithmValidationResult(
                            false, config.providerId(), resolvedKeyAlg, resolvedKeySize, signatureAlgorithm,
                            genMechName, caps.supportedSignatureAlgorithms().getOrDefault(resolvedKeyAlg, List.of()),
                            "Key size " + resolvedKeySize + " bits for " + resolvedKeyAlg
                                    + " is NOT supported on HSM device '" + config.providerId()
                                    + "' (supported: " + allowed + ")");
                }
            }
        }

        // 3. Validate signatureAlgorithm if provided
        if (signatureAlgorithm == null || signatureAlgorithm.isBlank()) {
            List<String> compatible = resolvedKeyAlg != null
                    ? caps.supportedSignatureAlgorithms().getOrDefault(resolvedKeyAlg, List.of())
                    : caps.signatureAlgorithms().stream()
                            .filter(ProviderCapabilities.SignatureAlgorithmCapability::supported)
                            .map(ProviderCapabilities.SignatureAlgorithmCapability::algorithm)
                            .toList();
            if (resolvedKeyAlg == null) {
                return new ProviderCapabilities.AlgorithmValidationResult(
                        false, config.providerId(), null, resolvedKeySize, null, null, compatible,
                        "Select a key algorithm or signing algorithm to verify support");
            }
            boolean hasAny = !compatible.isEmpty();
            return new ProviderCapabilities.AlgorithmValidationResult(
                    hasAny, config.providerId(), resolvedKeyAlg, resolvedKeySize, null,
                    null, compatible,
                    hasAny ? "Key algorithm '" + resolvedKeyAlg + "' is supported on device '" + config.providerId() + "'"
                           : "No signing algorithms are supported for " + resolvedKeyAlg + " on device '" + config.providerId() + "'");
        }

        String trimmedSig = signatureAlgorithm.trim();
        SignatureStrategy strategy;
        try {
            strategy = signatureStrategies.resolve(trimmedSig);
        } catch (IllegalArgumentException e) {
            List<String> compatible = resolvedKeyAlg != null
                    ? caps.supportedSignatureAlgorithms().getOrDefault(resolvedKeyAlg, List.of())
                    : List.of();
            return new ProviderCapabilities.AlgorithmValidationResult(
                    false, config.providerId(), resolvedKeyAlg, resolvedKeySize, trimmedSig, null, compatible,
                    e.getMessage());
        }

        String targetKeyType = resolvedKeyAlg != null ? resolvedKeyAlg : strategy.keyType();
        List<String> compatible = caps.supportedSignatureAlgorithms().getOrDefault(targetKeyType, List.of());
        long reqMech = strategy.requiredMechanism(trimmedSig, config.prehashInJvm());
        String reqMechName = Pkcs11Constants.mechanismName(reqMech);

        if (resolvedKeyAlg != null && !strategy.keyType().equalsIgnoreCase(resolvedKeyAlg)) {
            return new ProviderCapabilities.AlgorithmValidationResult(
                    false, config.providerId(), resolvedKeyAlg, resolvedKeySize, trimmedSig, reqMechName, compatible,
                    "Signature algorithm '" + trimmedSig + "' requires a " + strategy.keyType()
                            + " key, but key/selection is " + resolvedKeyAlg + ". Compatible algorithms: " + compatible);
        }

        MechanismInfo mechInfo = mechs.get(reqMech);
        if (mechInfo == null || !mechInfo.supportsSign()) {
            return new ProviderCapabilities.AlgorithmValidationResult(
                    false, config.providerId(), targetKeyType, resolvedKeySize, trimmedSig, reqMechName, compatible,
                    "Signature algorithm '" + trimmedSig + "' requires PKCS#11 mechanism " + reqMechName
                            + ", which is NOT supported by HSM device '" + config.providerId()
                            + "' (slot " + slotId + "). Supported for " + targetKeyType + ": " + compatible);
        }

        return new ProviderCapabilities.AlgorithmValidationResult(
                true, config.providerId(), targetKeyType, resolvedKeySize, trimmedSig, reqMechName, compatible,
                "Supported on HSM device '" + config.providerId() + "' via " + reqMechName
                        + (mechInfo.isHardware() ? " (hardware)" : ""));
    }

    public SubjectPublicKeyInfo generateKeyPair(String keyLabel, String keyAlgorithm, int keySize) {
        String cleanLabel = requireNonBlank(keyLabel, "keyLabel");
        KeyPairStrategy strategy = keyPairStrategies.resolve(keyAlgorithm);
        assertKeyPairSupported(strategy, keySize);
        return sessionPool.withRwSession(session -> {
            if (objectStore.findByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel).isPresent()) {
                throw new IllegalArgumentException(
                        "Key label '" + cleanLabel + "' already exists on provider '" + config.providerId() + "'");
            }
            byte[] keyId = cleanLabel.getBytes(StandardCharsets.UTF_8);
            long[] pair = strategy.generate(library, session, cleanLabel, keyId, keySize);
            log.info("Generated {} ({}-bit) keypair '{}' on provider '{}' (pubHandle={}, privHandle={})",
                    strategy.keyAlgorithmName(), keySize, cleanLabel, config.providerId(), pair[0], pair[1]);
            return objectStore.extractSubjectPublicKeyInfo(session, pair[0]);
        });
    }

    public SubjectPublicKeyInfo getPublicKey(String keyLabel) {
        return sessionPool.withSession(session -> objectStore.readPublicKey(session, keyLabel, config.providerId()));
    }

    public String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
        return generateCsr(keyLabel, subjectDn, keyAlgorithm, keySize, null, reuseExistingKey);
    }

    public String generateCsr(
            String keyLabel,
            String subjectDn,
            String keyAlgorithm,
            int keySize,
            String signatureAlgorithm,
            boolean reuseExistingKey) {
        String cleanLabel = requireNonBlank(keyLabel, "Key label");
        String cleanDn = requireNonBlank(subjectDn, "Subject DN");

        SubjectPublicKeyInfo spki;
        String resolvedSigAlg;

        if (reuseExistingKey) {
            spki = sessionPool.withSession(session -> {
                if (objectStore.findByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel).isEmpty()) {
                    throw new IllegalArgumentException(
                            "Existing private key '" + cleanLabel + "' not found on provider '" + config.providerId() + "'");
                }
                return objectStore.readPublicKey(session, cleanLabel, config.providerId());
            });
            String existingKeyType = X9ObjectIdentifiers.id_ecPublicKey.equals(spki.getAlgorithm().getAlgorithm())
                    ? "EC" : "RSA";
            resolvedSigAlg = resolveAndVerifyCsrSignatureAlgorithm(existingKeyType, signatureAlgorithm);
        } else {
            KeyPairStrategy strategy = keyPairStrategies.resolve(keyAlgorithm);
            assertKeyPairSupported(strategy, keySize);
            // Validate CSR signing algorithm BEFORE generating the keypair so we never leave an orphan key
            resolvedSigAlg = resolveAndVerifyCsrSignatureAlgorithm(strategy.keyAlgorithmName(), signatureAlgorithm);
            spki = generateKeyPair(cleanLabel, strategy.keyAlgorithmName(), keySize);
        }

        return Pkcs11CsrGenerator.generatePem(cleanDn, spki, createContentSigner(cleanLabel, resolvedSigAlg));
    }

    public void importCertificate(String keyLabel, X509CertificateHolder certHolder) {
        if (keyLabel == null || keyLabel.isBlank() || certHolder == null) {
            throw new IllegalArgumentException("keyLabel and certificate are required");
        }
        String cleanLabel = keyLabel.trim();

        sessionPool.withRwSession(session -> {
            if (objectStore.findByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel).isEmpty()) {
                throw new IllegalArgumentException(
                        "Private key '" + cleanLabel + "' not found on provider '" + config.providerId() + "'");
            }

            Optional<Long> existingPub = objectStore.findByClassAndLabel(session, Pkcs11Constants.CKO_PUBLIC_KEY, cleanLabel);
            if (existingPub.isPresent()) {
                verifyMatchingPublicKey(objectStore.extractSubjectPublicKeyInfo(session, existingPub.get()), certHolder, cleanLabel);
            }

            try {
                List<Pkcs11Attribute> template = List.of(
                        Pkcs11Attribute.ofUlong(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_CERTIFICATE),
                        Pkcs11Attribute.ofUlong(Pkcs11Constants.CKA_CERTIFICATE_TYPE, Pkcs11Constants.CKC_X_509),
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_TOKEN, true),
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_PRIVATE, false),
                        Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, cleanLabel),
                        Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_ID, cleanLabel.getBytes(StandardCharsets.UTF_8)),
                        Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_SUBJECT, certHolder.getSubject().getEncoded()),
                        Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_VALUE, certHolder.getEncoded())
                );
                long handle = library.cCreateObject(session, template);
                log.info("Stored X.509 certificate (serial={}, objHandle={}) in token '{}' under keyLabel='{}'",
                        certHolder.getSerialNumber().toString(16), handle, initialTokenInfo.label(), cleanLabel);
                return handle;
            } catch (Pkcs11Exception e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("Failed to encode X.509 certificate for token import", e);
            }
        });
    }

    public byte[] sign(String keyLabel, String signatureAlgorithm, byte[] data) {
        String cleanLabel = requireNonBlank(keyLabel, "keyLabel");
        String resolvedAlg = requireNonBlank(signatureAlgorithm, "signatureAlgorithm");
        SignatureStrategy strategy = signatureStrategies.resolve(resolvedAlg);
        assertSignatureMechanismSupported(strategy, resolvedAlg);

        return sessionPool.withSession(session -> {
            long keyHandle = objectStore.findByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel)
                    .orElseThrow(() -> new IllegalStateException(
                            "Private key '" + cleanLabel + "' not found on provider '" + config.providerId() + "'"));
            long actualKeyType = library.cGetAttributeUlong(session, keyHandle, Pkcs11Constants.CKA_KEY_TYPE);
            if (actualKeyType != strategy.pkcs11KeyType()) {
                throw new IllegalArgumentException(
                        "Cannot sign with algorithm '" + resolvedAlg + "' (requires " + strategy.keyType()
                                + " key): HSM private key '" + cleanLabel + "' on provider '" + config.providerId()
                                + "' has key type " + Pkcs11Constants.keyTypeName(actualKeyType));
            }
            return strategy.sign(library, session, keyHandle, resolvedAlg, data, config.prehashInJvm());
        });
    }

    public Pkcs11ContentSigner createContentSigner(String keyLabel, String signatureAlgorithm) {
        return new Pkcs11ContentSigner(this, keyLabel, signatureAlgorithm);
    }

    @Override
    public void close() {
        cachedMechanisms = null;
        try {
            sessionPool.close();
        } finally {
            if (onCloseCallback != null) {
                onCloseCallback.run();
            }
        }
    }

    private Map<Long, MechanismInfo> getSlotMechanisms() {
        Map<Long, MechanismInfo> cached = this.cachedMechanisms;
        if (cached != null) {
            return cached;
        }
        long[] codes = library.cGetMechanismList(slotId);
        Map<Long, MechanismInfo> loaded = new HashMap<>();
        if (codes != null) {
            for (long code : codes) {
                try {
                    loaded.put(code, library.cGetMechanismInfo(slotId, code));
                } catch (RuntimeException e) {
                    log.debug("C_GetMechanismInfo failed for {} on slot {}: {}",
                            Pkcs11Constants.mechanismName(code), slotId, e.getMessage());
                }
            }
        }
        Map<Long, MechanismInfo> unmodifiable = Collections.unmodifiableMap(loaded);
        this.cachedMechanisms = unmodifiable;
        return unmodifiable;
    }

    private void assertKeyPairSupported(KeyPairStrategy strategy, int keySize) {
        Map<Long, MechanismInfo> mechs = getSlotMechanisms();
        long genMech = strategy.keyPairGenMechanism();
        String mechName = Pkcs11Constants.mechanismName(genMech);
        MechanismInfo info = mechs.get(genMech);
        if (info == null || !info.supportsKeyPairGen()) {
            throw new IllegalArgumentException(
                    "Key algorithm '" + strategy.keyAlgorithmName() + "' is not supported by HSM provider '"
                            + config.providerId() + "' (slot " + slotId + " lacks " + mechName + ")");
        }
        if (!strategy.supportedKeySizes().contains(keySize) || !info.supportsKeySize(keySize)) {
            List<Integer> allowed = strategy.supportedKeySizes().stream().filter(info::supportsKeySize).toList();
            throw new IllegalArgumentException(
                    "Key size " + keySize + " bits for " + strategy.keyAlgorithmName()
                            + " is not supported by HSM provider '" + config.providerId()
                            + "' (supported: " + allowed + ")");
        }
    }

    private void assertSignatureMechanismSupported(SignatureStrategy strategy, String signatureAlgorithm) {
        Map<Long, MechanismInfo> mechs = getSlotMechanisms();
        long reqMech = strategy.requiredMechanism(signatureAlgorithm, config.prehashInJvm());
        String mechName = Pkcs11Constants.mechanismName(reqMech);
        MechanismInfo info = mechs.get(reqMech);
        if (info == null || !info.supportsSign()) {
            throw new IllegalArgumentException(
                    "Signature algorithm '" + signatureAlgorithm + "' is not supported by HSM provider '"
                            + config.providerId() + "' (slot " + slotId + " lacks signing mechanism " + mechName + ")");
        }
    }

    private String resolveAndVerifyCsrSignatureAlgorithm(String keyType, String requestedSigAlg) {
        ProviderCapabilities caps = getCapabilities();
        List<String> supportedForType = caps.supportedSignatureAlgorithms().getOrDefault(keyType, List.of());
        if (requestedSigAlg == null || requestedSigAlg.isBlank()) {
            if (supportedForType.isEmpty()) {
                throw new IllegalArgumentException(
                        "No supported signing mechanisms found for " + keyType
                                + " keys on HSM provider '" + config.providerId() + "' (slot " + slotId + ")");
            }
            return supportedForType.get(0);
        }
        String trimmed = requestedSigAlg.trim();
        SignatureStrategy strategy = signatureStrategies.resolve(trimmed);
        if (!strategy.keyType().equalsIgnoreCase(keyType)) {
            throw new IllegalArgumentException(
                    "Signature algorithm '" + trimmed + "' requires a " + strategy.keyType()
                            + " key, but target key is " + keyType + ". Supported: " + supportedForType);
        }
        assertSignatureMechanismSupported(strategy, trimmed);
        return trimmed;
    }

    private static void verifyMatchingPublicKey(
            SubjectPublicKeyInfo tokenSpki,
            X509CertificateHolder certHolder,
            String keyLabel) {
        try {
            if (!Arrays.equals(tokenSpki.getEncoded(), certHolder.getSubjectPublicKeyInfo().getEncoded())) {
                throw new IllegalArgumentException(
                        "Imported certificate public key does not match private key '" + keyLabel + "'");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed comparing certificate public key", e);
        }
    }

    private static TokenResolution resolveSlot(Pkcs11LibraryPort library, Pkcs11ProviderConfig config) {
        if (config.slotId() != null) {
            return new TokenResolution(config.slotId(), library.cGetTokenInfo(config.slotId()));
        }
        long[] slots = library.cGetSlotList(true);
        if (slots == null || slots.length == 0) {
            throw new IllegalStateException("No PKCS#11 tokens present for library " + config.libraryPath());
        }
        if (config.tokenLabel() != null && !config.tokenLabel().isBlank()) {
            String target = config.tokenLabel().trim();
            for (long slot : slots) {
                TokenInfo info = library.cGetTokenInfo(slot);
                if (target.equals(info.label().trim())) {
                    return new TokenResolution(slot, info);
                }
            }
            throw new IllegalStateException(
                    "No PKCS#11 token found with label '" + target + "' in library " + config.libraryPath());
        }
        int idx = config.slotListIndex();
        if (idx < 0 || idx >= slots.length) {
            throw new IllegalStateException(
                    "slotListIndex=" + idx + " out of range for library " + config.libraryPath()
                            + " (" + slots.length + " token slots found)");
        }
        long chosen = slots[idx];
        return new TokenResolution(chosen, library.cGetTokenInfo(chosen));
    }

    private static String requireNonBlank(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be blank");
        }
        return value.trim();
    }

    private record TokenResolution(long slotId, TokenInfo tokenInfo) {}
}

