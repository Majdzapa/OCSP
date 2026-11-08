package com.company.incert.ocsp.signing.adapter.out;

import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
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
 * PKCS#11 (SoftHSM2) backed OcspSigner adapter.
 * Accesses keys in the token using SunPKCS11 provider.
 * Private key is non-extractable and never leaves the token.
 */
@Slf4j
public class Pkcs11OcspSigner implements OcspSigner {

    private final String pkcs11ConfigPath;
    private final String tokenLabel;
    private final char[] pin;
    private final String keyLabel;
    private final String libraryPath;

    private final AtomicReference<SignerState> stateRef = new AtomicReference<>();

    public Pkcs11OcspSigner(String libraryPath, String tokenLabel, String pin, String keyLabel) {
        this.libraryPath = libraryPath;
        this.tokenLabel = tokenLabel;
        this.pin = pin != null ? pin.toCharArray() : new char[0];
        this.keyLabel = keyLabel;
        this.pkcs11ConfigPath = createConfigFileIfNecessary(libraryPath, tokenLabel);
        load();
    }

    private String createConfigFileIfNecessary(String libraryPath, String tokenLabel) {
        if (libraryPath != null && libraryPath.endsWith(".cfg")) {
            return libraryPath;
        }
        try {
            File cfgFile = File.createTempFile("sunpkcs11-", ".cfg");
            cfgFile.deleteOnExit();
            try (FileWriter fw = new FileWriter(cfgFile)) {
                fw.write("name = SoftHSM\n");
                fw.write("library = " + (libraryPath != null ? libraryPath : "/usr/lib/softhsm/libsofthsm2.so") + "\n");
                if (tokenLabel != null && !tokenLabel.isBlank()) {
                    fw.write("slotListIndex = 0\n");
                }
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
            Provider provider = sunPkcs11.configure(pkcs11ConfigPath);
            Security.addProvider(provider);

            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, pin);

            PrivateKey privateKey = (PrivateKey) ks.getKey(keyLabel, pin);
            if (privateKey == null) {
                log.warn("Key '{}' not found in PKCS#11 keystore. Available aliases: {}",
                    keyLabel, java.util.Collections.list(ks.aliases()));
                throw new IllegalStateException("Key '" + keyLabel + "' not found in PKCS#11 keystore");
            }

            java.security.cert.Certificate cert = ks.getCertificate(keyLabel);
            if (cert == null) {
                throw new IllegalStateException("Certificate for key '" + keyLabel + "' not found in PKCS#11 keystore");
            }

            X509Certificate x509 = (X509Certificate) cert;
            X509CertificateHolder holder = new X509CertificateHolder(x509.getEncoded());
            String algorithm = x509.getPublicKey().getAlgorithm().equalsIgnoreCase("EC")
                ? "SHA256withECDSA" : "SHA256withRSA";

            stateRef.set(new SignerState(
                privateKey,
                new X509CertificateHolder[]{holder},
                algorithm,
                x509.getNotAfter().toInstant(),
                provider
            ));
            log.info("PKCS#11 signer loaded successfully: keyLabel={} algorithm={} notAfter={}",
                keyLabel, algorithm, x509.getNotAfter());
        } catch (Exception e) {
            log.error("Failed to load PKCS#11 signing key: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to load PKCS#11 signing key: " + e.getMessage(), e);
        }
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

