package com.company.incert.ocsp.signing.pkcs11;

import com.company.incert.ocsp.signing.pkcs11.crypto.KeyPairStrategies;
import com.company.incert.ocsp.signing.pkcs11.crypto.KeyPairStrategy;
import com.company.incert.ocsp.signing.pkcs11.crypto.Pkcs11CsrGenerator;
import com.company.incert.ocsp.signing.pkcs11.crypto.SignatureStrategies;
import com.company.incert.ocsp.signing.pkcs11.crypto.SignatureStrategy;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

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

    public SubjectPublicKeyInfo generateKeyPair(String keyLabel, String keyAlgorithm, int keySize) {
        String cleanLabel = requireNonBlank(keyLabel, "keyLabel");
        KeyPairStrategy strategy = keyPairStrategies.resolve(keyAlgorithm);
        return sessionPool.withRwSession(session -> {
            if (objectStore.findByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel).isPresent()) {
                throw new IllegalArgumentException(
                        "Key label '" + cleanLabel + "' already exists on provider '" + config.providerId() + "'");
            }
            byte[] keyId = cleanLabel.getBytes(StandardCharsets.UTF_8);
            long[] pair = strategy.generate(library, session, cleanLabel, keyId, keySize);
            log.info("Generated {} keypair '{}' on provider '{}' (pubHandle={}, privHandle={})",
                    keyAlgorithm, cleanLabel, config.providerId(), pair[0], pair[1]);
            return objectStore.extractSubjectPublicKeyInfo(session, pair[0]);
        });
    }

    public SubjectPublicKeyInfo getPublicKey(String keyLabel) {
        return sessionPool.withSession(session -> objectStore.readPublicKey(session, keyLabel, config.providerId()));
    }

    public String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
        String cleanLabel = requireNonBlank(keyLabel, "Key label");
        String cleanDn = requireNonBlank(subjectDn, "Subject DN");

        SubjectPublicKeyInfo spki;
        String sigAlg;

        if (reuseExistingKey) {
            spki = sessionPool.withSession(session -> {
                if (objectStore.findByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel).isEmpty()) {
                    throw new IllegalArgumentException(
                            "Existing private key '" + cleanLabel + "' not found on provider '" + config.providerId() + "'");
                }
                return objectStore.readPublicKey(session, cleanLabel, config.providerId());
            });
            boolean isEc = X9ObjectIdentifiers.id_ecPublicKey.equals(spki.getAlgorithm().getAlgorithm());
            sigAlg = isEc ? "SHA256withECDSA" : "SHA256withRSA";
        } else {
            KeyPairStrategy strategy = keyPairStrategies.resolve(keyAlgorithm);
            spki = generateKeyPair(cleanLabel, keyAlgorithm, keySize);
            sigAlg = strategy.defaultSignatureAlgorithm();
        }

        return Pkcs11CsrGenerator.generatePem(cleanDn, spki, createContentSigner(cleanLabel, sigAlg));
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
        SignatureStrategy strategy = signatureStrategies.resolve(signatureAlgorithm);
        String resolvedAlg = (signatureAlgorithm != null && !signatureAlgorithm.isBlank())
                ? signatureAlgorithm.trim()
                : "SHA256withRSA";

        return sessionPool.withSession(session -> {
            long keyHandle = objectStore.findByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel)
                    .orElseThrow(() -> new IllegalStateException(
                            "Private key '" + cleanLabel + "' not found on provider '" + config.providerId() + "'"));
            return strategy.sign(library, session, keyHandle, resolvedAlg, data, config.prehashInJvm());
        });
    }

    public Pkcs11ContentSigner createContentSigner(String keyLabel, String signatureAlgorithm) {
        return new Pkcs11ContentSigner(this, keyLabel, signatureAlgorithm);
    }

    @Override
    public void close() {
        try {
            sessionPool.close();
        } finally {
            if (onCloseCallback != null) {
                onCloseCallback.run();
            }
        }
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

