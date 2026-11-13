package com.company.incert.ocsp.signing;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileWriter;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * PKCS#11 (SoftHSM2) backed OcspSigner.
 * Accesses keys in the token using SunPKCS11 provider.
 * Private key is non-extractable and never leaves the token.
 * Supports dynamic switching of the active signing certificate/key at runtime.
 */
@Slf4j
public class Pkcs11OcspSigner implements OcspSigner {

    private final String pkcs11ConfigPath;
    private final String tokenLabel;
    private final char[] pin;
    private volatile String keyLabel;

    private volatile KeyStore keyStore;
    private volatile Provider provider;

    private final AtomicReference<SignerState> stateRef = new AtomicReference<>();

    public Pkcs11OcspSigner(String libraryPath, String tokenLabel, String pin, String keyLabel) {
        this(libraryPath, tokenLabel, pin, keyLabel, 0, null);
    }

    public Pkcs11OcspSigner(String libraryPath, String tokenLabel, String pin, String keyLabel, int slotListIndex, String configPath) {
        this.tokenLabel = tokenLabel;
        this.pin = pin != null ? pin.toCharArray() : new char[0];
        this.keyLabel = keyLabel;
        this.pkcs11ConfigPath = (configPath != null && !configPath.isBlank())
                ? configPath
                : createConfigFileIfNecessary(libraryPath, tokenLabel, slotListIndex);
        load();
    }

    private String createConfigFileIfNecessary(String libraryPath, String tokenLabel, int slotListIndex) {
        if (libraryPath != null && libraryPath.endsWith(".cfg")) {
            return libraryPath;
        }
        try {
            File cfgFile = File.createTempFile("sunpkcs11-", ".cfg");
            cfgFile.deleteOnExit();
            try (FileWriter fw = new FileWriter(cfgFile)) {
                fw.write("name = SoftHSM\n");
                fw.write("library = " + (libraryPath != null ? libraryPath : "/usr/lib/softhsm/libsofthsm2.so") + "\n");
                fw.write("slotListIndex = " + slotListIndex + "\n");
            }
            return cfgFile.getAbsolutePath();
        } catch (Exception e) {
            log.warn("Could not create temp PKCS11 config: {}", e.getMessage());
            return "/etc/softhsm2/pkcs11.cfg";
        }
    }

    public synchronized void load() {
        try {
            log.info("Initializing PKCS#11 provider with config={}, token={}, keyLabel={}",
                pkcs11ConfigPath, tokenLabel, keyLabel);

            Provider sunPkcs11 = Security.getProvider("SunPKCS11");
            if (sunPkcs11 == null) {
                throw new IllegalStateException("SunPKCS11 provider not available in JDK");
            }
            this.provider = sunPkcs11.configure(pkcs11ConfigPath);
            Security.addProvider(this.provider);

            this.keyStore = KeyStore.getInstance("PKCS11", this.provider);
            this.keyStore.load(null, pin);

            updateActiveCertificate(this.keyLabel, null);
        } catch (Exception e) {
            log.error("Failed to load PKCS#11 signing key: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to load PKCS#11 signing key: " + e.getMessage(), e);
        }
    }

    @Override
    public synchronized void updateActiveCertificate(String newKeyLabel, X509CertificateHolder certificate) {
        if (newKeyLabel != null && !newKeyLabel.isBlank()) {
            this.keyLabel = newKeyLabel;
        }

        try {
            if (this.keyStore == null) {
                log.warn("PKCS#11 keyStore was null, reloading...");
                load();
                return;
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(this.keyLabel, pin);
            if (privateKey == null) {
                log.warn("Key '{}' not found in PKCS#11 keystore. Available aliases: {}",
                    this.keyLabel, java.util.Collections.list(keyStore.aliases()));
                throw new IllegalStateException("Key '" + this.keyLabel + "' not found in PKCS#11 keystore");
            }

            X509CertificateHolder holder = certificate;
            if (holder == null) {
                java.security.cert.Certificate cert = keyStore.getCertificate(this.keyLabel);
                if (cert == null) {
                    throw new IllegalStateException("Certificate for key '" + this.keyLabel + "' not found in PKCS#11 keystore");
                }
                holder = new X509CertificateHolder(cert.getEncoded());
            }

            String algorithm = "SHA256withRSA";
            try {
                if (holder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId().contains("1.2.840.10045")) {
                    algorithm = "SHA256withECDSA";
                }
            } catch (Exception ignored) {}

            stateRef.set(new SignerState(
                privateKey,
                new X509CertificateHolder[]{holder},
                algorithm,
                holder.getNotAfter().toInstant(),
                this.provider
            ));
            log.info("Active PKCS#11 signing certificate updated: keyLabel={} algorithm={} notAfter={}",
                this.keyLabel, algorithm, holder.getNotAfter());
        } catch (Exception e) {
            log.error("Failed to update active signing certificate: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to update active signing certificate: " + e.getMessage(), e);
        }
    }

    @Override
    public String getActiveKeyLabel() {
        return this.keyLabel;
    }

    @Override
    public ContentSigner createContentSigner() throws Exception {
        SignerState state = requireState();
        return new JcaContentSignerBuilder(state.algorithm())
            .setProvider(state.provider())
            .build(state.privateKey());
    }

    @Override
    public X509CertificateHolder[] getSignerChain() {
        return requireState().chain();
    }

    @Override
    public long signingCertDaysUntilExpiry() {
        SignerState state = stateRef.get();
        if (state == null) return -1;
        return ChronoUnit.DAYS.between(Instant.now(), state.notAfter());
    }

    @Override
    public String type() {
        return "PKCS11";
    }

    private SignerState requireState() {
        SignerState state = stateRef.get();
        if (state == null) {
            throw new IllegalStateException("PKCS#11 signer not initialized");
        }
        return state;
    }

    private record SignerState(
        PrivateKey privateKey,
        X509CertificateHolder[] chain,
        String algorithm,
        Instant notAfter,
        Provider provider
    ) {}
}
