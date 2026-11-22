package com.company.incert.ocsp.signing.hsm;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * PKCS#11 (SoftHSM2 / Hardware HSM) backed OcspSigner.
 * Accesses keys in the token using SunPKCS11 provider.
 * Private key is non-extractable and never leaves the token.
 * Supports keypair generation, PKCS#10 CSR creation, certificate import,
 * and dynamic switching of the active signing certificate/key at runtime.
 */
@Slf4j
public class Pkcs11OcspSigner implements OcspSigner {

    private final String libraryPath;
    private final String pkcs11ConfigPath;
    private final String tokenLabel;
    private final int slotListIndex;
    private final char[] pin;
    private volatile String keyLabel;

    private volatile KeyStore keyStore;
    private volatile Provider provider;

    private final AtomicReference<SignerState> stateRef = new AtomicReference<>();
    private final List<RegisteredSignerEntry> registeredSigners = new CopyOnWriteArrayList<>();

    public Pkcs11OcspSigner(String libraryPath, String tokenLabel, String pin, String keyLabel) {
        this(libraryPath, tokenLabel, pin, keyLabel, 0, null);
    }

    public Pkcs11OcspSigner(String libraryPath, String tokenLabel, String pin, String keyLabel, int slotListIndex, String configPath) {
        boolean hasConfig = configPath != null && !configPath.isBlank();
        boolean hasLibrary = libraryPath != null && !libraryPath.isBlank();
        if (!hasConfig && !hasLibrary) {
            throw new IllegalArgumentException("hsm.pkcs11-library or hsm.config-path must be configured");
        }
        this.libraryPath = hasLibrary ? resolveResourcePath(libraryPath.trim()) : null;
        this.tokenLabel = tokenLabel;
        this.slotListIndex = slotListIndex;
        this.pin = pin != null ? pin.toCharArray() : new char[0];
        this.keyLabel = keyLabel;
        this.pkcs11ConfigPath = hasConfig
                ? resolveResourcePath(configPath.trim())
                : createConfigFile(this.libraryPath, slotListIndex);
        load();
    }

    private static String resolveResourcePath(String path) {
        if (!path.startsWith("classpath:")) {
            return path;
        }
        String resourceName = path.substring("classpath:".length()).replaceFirst("^/+", "");
        String fileName = resourceName.contains("/")
                ? resourceName.substring(resourceName.lastIndexOf('/') + 1)
                : resourceName;
        try (InputStream is = Pkcs11OcspSigner.class.getClassLoader().getResourceAsStream(resourceName)) {
            if (is == null) {
                throw new IllegalStateException("Classpath resource not found: " + path);
            }
            java.nio.file.Path tempDir = Files.createTempDirectory("pkcs11-res-");
            tempDir.toFile().deleteOnExit();
            java.nio.file.Path targetFile = tempDir.resolve(fileName);
            targetFile.toFile().deleteOnExit();
            Files.copy(is, targetFile, StandardCopyOption.REPLACE_EXISTING);
            return targetFile.toAbsolutePath().toString();
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to extract classpath resource " + path + ": " + e.getMessage(), e);
        }
    }

    private String createConfigFile(String resolvedLibraryPath, int slotListIndex) {
        try {
            File cfgFile = File.createTempFile("sunpkcs11-", ".cfg");
            cfgFile.deleteOnExit();
            try (FileWriter fw = new FileWriter(cfgFile)) {
                fw.write("name = SoftHSM\n");
                fw.write("library = " + resolvedLibraryPath + "\n");
                fw.write("slotListIndex = " + slotListIndex + "\n");
            }
            return cfgFile.getAbsolutePath();
        } catch (Exception e) {
            throw new IllegalStateException("Could not create SunPKCS11 config for library " + resolvedLibraryPath, e);
        }
    }

    public String getLibraryPath() {
        return libraryPath;
    }

    public String getTokenLabel() {
        return tokenLabel;
    }

    public int getSlotListIndex() {
        return slotListIndex;
    }

    public synchronized void load() {
        try {
            log.info("Initializing PKCS#11 provider with config={}, library={}, token={}, keyLabel={}",
                pkcs11ConfigPath, libraryPath, tokenLabel, keyLabel);

            Provider sunPkcs11 = Security.getProvider("SunPKCS11");
            if (sunPkcs11 == null) {
                throw new IllegalStateException("SunPKCS11 provider not available in JDK");
            }
            this.provider = sunPkcs11.configure(pkcs11ConfigPath);
            Security.addProvider(this.provider);

            this.keyStore = KeyStore.getInstance("PKCS11", this.provider);
            this.keyStore.load(null, pin);

            if (keyStore.containsAlias(this.keyLabel) && keyStore.getKey(this.keyLabel, pin) != null) {
                updateActiveCertificate(this.keyLabel, null);
            } else {
                // Nothing is pre-provisioned: the user generates a CSR in the HSM, has it signed by a CA,
                // then imports and activates the resulting certificate.
                log.info("No signing key '{}' in HSM token '{}'. Generate a CSR, have it signed by your CA, "
                        + "then import and activate the certificate. OCSP requests answer tryLater until then.",
                        this.keyLabel, tokenLabel);
            }
        } catch (Exception e) {
            log.error("Failed to load PKCS#11 signing key: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to load PKCS#11 signing key: " + e.getMessage(), e);
        }
    }

    @Override
    public synchronized List<String> listKeyLabels() {
        if (this.keyStore == null) {
            return List.of();
        }
        try {
            return Collections.list(this.keyStore.aliases());
        } catch (KeyStoreException e) {
            log.warn("Failed to list PKCS#11 aliases: {}", e.getMessage());
            return List.of();
        }
    }

    @Override
    public synchronized java.util.Map<String, String> getKeyAlgorithms() {
        if (this.keyStore == null) {
            return java.util.Map.of();
        }
        java.util.Map<String, String> result = new java.util.LinkedHashMap<>();
        try {
            for (String alias : Collections.list(this.keyStore.aliases())) {
                Certificate cert = this.keyStore.getCertificate(alias);
                if (cert != null && cert.getPublicKey() != null) {
                    result.put(alias, cert.getPublicKey().getAlgorithm());
                }
            }
        } catch (KeyStoreException e) {
            log.warn("Failed to read PKCS#11 key algorithms: {}", e.getMessage());
        }
        return result;
    }

    @Override
    public synchronized String generateCsr(String targetKeyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
        if (targetKeyLabel == null || targetKeyLabel.isBlank()) {
            throw new IllegalArgumentException("Key label is required");
        }
        if (subjectDn == null || subjectDn.isBlank()) {
            throw new IllegalArgumentException("Subject DN is required");
        }
        String cleanLabel = targetKeyLabel.trim();
        String alg = (keyAlgorithm != null && !keyAlgorithm.isBlank()) ? keyAlgorithm.trim().toUpperCase() : "RSA";

        try {
            if (this.keyStore == null) {
                load();
            }

            PrivateKey privateKey;
            PublicKey publicKey;
            String sigAlg;

            boolean exists = keyStore.containsAlias(cleanLabel);
            if (exists) {
                if (!reuseExistingKey) {
                    throw new IllegalArgumentException("Key label '" + cleanLabel + "' already exists in HSM token. Choose a new label or enable reuse.");
                }
                privateKey = (PrivateKey) keyStore.getKey(cleanLabel, pin);
                Certificate existingCert = keyStore.getCertificate(cleanLabel);
                if (privateKey == null || existingCert == null) {
                    throw new IllegalStateException("Existing key or certificate for '" + cleanLabel + "' could not be loaded from HSM token");
                }
                publicKey = existingCert.getPublicKey();
                sigAlg = "EC".equalsIgnoreCase(privateKey.getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA";
                log.info("Reusing existing HSM keypair '{}' (algorithm={}) for CSR generation", cleanLabel, privateKey.getAlgorithm());
            } else {
                GeneratedKeyPair generated = generateAndStoreKeyPair(cleanLabel, subjectDn.trim(), alg, keySize);
                privateKey = generated.privateKey();
                publicKey = generated.publicKey();
                sigAlg = generated.sigAlg();
            }

            ContentSigner csrSigner = new JcaContentSignerBuilder(sigAlg)
                    .setProvider(this.provider)
                    .build(privateKey);

            PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                    new X500Name(subjectDn.trim()),
                    publicKey
            ).build(csrSigner);

            try (StringWriter sw = new StringWriter(); JcaPEMWriter pw = new JcaPEMWriter(sw)) {
                pw.writeObject(csr);
                pw.flush();
                return sw.toString();
            }
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to generate CSR in HSM for keyLabel='{}': {}", cleanLabel, e.getMessage(), e);
            throw new RuntimeException("Failed to generate CSR in HSM: " + e.getMessage(), e);
        }
    }

    @Override
    public synchronized void importCertificateToToken(String targetKeyLabel, X509CertificateHolder certificateHolder) {
        if (targetKeyLabel == null || targetKeyLabel.isBlank() || certificateHolder == null) {
            return;
        }
        String cleanLabel = targetKeyLabel.trim();
        try {
            if (this.keyStore == null) {
                load();
            }
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(cleanLabel, pin);
            if (privateKey == null) {
                throw new IllegalArgumentException("Private key '" + cleanLabel + "' not found in HSM token. Available keys: " + listKeyLabels());
            }

            X509Certificate newCert = new JcaX509CertificateConverter().getCertificate(certificateHolder);
            Certificate existingCert = keyStore.getCertificate(cleanLabel);
            if (existingCert != null && !Arrays.equals(existingCert.getPublicKey().getEncoded(), newCert.getPublicKey().getEncoded())) {
                throw new IllegalArgumentException("Imported certificate public key does not match the HSM private key '" + cleanLabel + "'");
            }

            keyStore.setKeyEntry(cleanLabel, privateKey, null, new Certificate[]{newCert});
            log.info("Imported signed certificate (serial={}) into HSM token under keyLabel='{}'",
                    certificateHolder.getSerialNumber().toString(16), cleanLabel);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to import certificate into HSM token for keyLabel='{}': {}", cleanLabel, e.getMessage(), e);
            throw new RuntimeException("Failed to import certificate into HSM token: " + e.getMessage(), e);
        }
    }

    private GeneratedKeyPair generateAndStoreKeyPair(String label, String subjectDn, String alg, int keySize) throws Exception {
        KeyPair kp;
        String sigAlg;
        if ("EC".equals(alg) || "ECDSA".equals(alg)) {
            String curve = (keySize == 384) ? "secp384r1" : "secp256r1";
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", this.provider);
            kpg.initialize(new ECGenParameterSpec(curve));
            kp = kpg.generateKeyPair();
            sigAlg = "SHA256withECDSA";
        } else {
            int rsaBits = (keySize == 2048 || keySize == 3072 || keySize == 4096) ? keySize : 3072;
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", this.provider);
            kpg.initialize(rsaBits);
            kp = kpg.generateKeyPair();
            sigAlg = "SHA256withRSA";
        }
        PrivateKey privateKey = kp.getPrivate();
        PublicKey publicKey = kp.getPublic();

        // SunPKCS11 requires a certificate entry alongside a PrivateKey to persist the alias in KeyStore
        X509Certificate placeholder = buildSelfSignedPlaceholder(subjectDn, publicKey, privateKey, sigAlg);
        keyStore.setKeyEntry(label, privateKey, null, new Certificate[]{placeholder});
        log.info("Generated new HSM keypair '{}' (alg={}, sigAlg={}) in token '{}'", label, alg, sigAlg, tokenLabel);
        return new GeneratedKeyPair(privateKey, publicKey, sigAlg);
    }

    private record GeneratedKeyPair(PrivateKey privateKey, PublicKey publicKey, String sigAlg) {}

    private X509Certificate buildSelfSignedPlaceholder(String subjectDn, PublicKey pubKey, PrivateKey privKey, String sigAlg) throws Exception {
        X500Name name = new X500Name(subjectDn);
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                name,
                BigInteger.valueOf(System.nanoTime()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(30, ChronoUnit.DAYS)),
                name,
                SubjectPublicKeyInfo.getInstance(pubKey.getEncoded())
        );
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider(this.provider).build(privKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Override
    public synchronized void updateActiveCertificate(String newKeyLabel, X509CertificateHolder certificate) {
        updateActiveCertificate(newKeyLabel, certificate, null);
    }

    @Override
    public synchronized void updateActiveCertificate(String newKeyLabel, X509CertificateHolder certificate, String signatureAlgorithm) {
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
                    this.keyLabel, Collections.list(keyStore.aliases()));
                throw new IllegalStateException("Key '" + this.keyLabel + "' not found in PKCS#11 keystore");
            }

            X509CertificateHolder holder = certificate;
            if (holder == null) {
                Certificate cert = keyStore.getCertificate(this.keyLabel);
                if (cert == null) {
                    throw new IllegalStateException("Certificate for key '" + this.keyLabel + "' not found in PKCS#11 keystore");
                }
                holder = new X509CertificateHolder(cert.getEncoded());
            }

            String algorithm = (signatureAlgorithm != null && !signatureAlgorithm.isBlank())
                    ? signatureAlgorithm.trim()
                    : detectSignatureAlgorithm(holder);

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
    public synchronized void syncRegisteredSigners(List<RegisteredSigner> signers) {
        if (this.keyStore == null || signers == null) {
            return;
        }
        List<RegisteredSignerEntry> updated = new java.util.ArrayList<>();
        for (RegisteredSigner rs : signers) {
            try {
                X509CertificateHolder holder = rs.certificate();
                if (holder == null || Instant.now().isAfter(holder.getNotAfter().toInstant())) {
                    continue;
                }
                PrivateKey pk = (PrivateKey) keyStore.getKey(rs.keyLabel(), pin);
                if (pk == null) {
                    log.warn("Skipping registered signer with missing HSM keyLabel='{}'", rs.keyLabel());
                    continue;
                }
                String alg = (rs.signatureAlgorithm() != null && !rs.signatureAlgorithm().isBlank())
                        ? rs.signatureAlgorithm().trim()
                        : detectSignatureAlgorithm(holder);
                byte[] issuerEncoded = holder.getIssuer().getEncoded();
                byte[] aki = extractAuthorityKeyId(holder);
                updated.add(new RegisteredSignerEntry(
                        rs.keyLabel(),
                        pk,
                        new X509CertificateHolder[]{holder},
                        alg,
                        holder.getNotAfter().toInstant(),
                        issuerEncoded,
                        aki,
                        rs.preferred()
                ));
            } catch (Exception e) {
                log.warn("Failed to load registered signer for keyLabel='{}': {}", rs.keyLabel(), e.getMessage());
            }
        }
        registeredSigners.clear();
        registeredSigners.addAll(updated);
        log.info("Synchronized {} non-expired signing certificates for multi-CA selection", registeredSigners.size());
    }

    @Override
    public SigningSelection selectSigner(CertificateID certId) throws Exception {
        if (registeredSigners.isEmpty()) {
            throw new SignerNotConfiguredException(
                    "No active signing certificate is configured (activate one under Signing Certificates)");
        }
        if (certId != null) {
            Instant now = Instant.now();
            byte[] reqIssuerNameHash = certId.getIssuerNameHash();
            byte[] reqIssuerKeyHash = certId.getIssuerKeyHash();
            ASN1ObjectIdentifier hashAlgOid = certId.getHashAlgOID();
            String digestName = resolveDigestName(hashAlgOid);

            if (digestName != null && reqIssuerNameHash != null) {
                MessageDigest md = MessageDigest.getInstance(digestName);
                RegisteredSignerEntry bestMatch = null;
                int bestScore = -1;

                for (RegisteredSignerEntry entry : registeredSigners) {
                    if (now.isAfter(entry.notAfter())) {
                        continue;
                    }
                    byte[] entryNameHash = md.digest(entry.issuerEncoded());
                    if (!Arrays.equals(entryNameHash, reqIssuerNameHash)) {
                        continue;
                    }

                    int score = 1; // Issuer DN matched
                    if (entry.authorityKeyId() != null && OIWObjectIdentifiers.idSHA1.equals(hashAlgOid)) {
                        if (Arrays.equals(entry.authorityKeyId(), reqIssuerKeyHash)) {
                            score = 3; // Both Issuer DN and AuthorityKeyIdentifier matched
                        } else {
                            continue; // Different CA key with same DN
                        }
                    }
                    if (entry.preferred()) {
                        score += 1;
                    }
                    if (score > bestScore) {
                        bestScore = score;
                        bestMatch = entry;
                    }
                }

                if (bestMatch != null) {
                    ContentSigner cs = new JcaContentSignerBuilder(bestMatch.algorithm())
                            .setProvider(this.provider)
                            .build(bestMatch.privateKey());
                    return new SigningSelection(bestMatch.chain(), cs);
                }
            }
        }

        SignerState fallback = requireState();
        ContentSigner cs = new JcaContentSignerBuilder(fallback.algorithm())
                .setProvider(fallback.provider())
                .build(fallback.privateKey());
        return new SigningSelection(fallback.chain(), cs);
    }

    private static String detectSignatureAlgorithm(X509CertificateHolder holder) {
        try {
            if (holder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId().contains("1.2.840.10045")) {
                return "SHA256withECDSA";
            }
        } catch (Exception ignored) {}
        return "SHA256withRSA";
    }

    private static byte[] extractAuthorityKeyId(X509CertificateHolder holder) {
        try {
            Extension ext = holder.getExtension(Extension.authorityKeyIdentifier);
            if (ext != null) {
                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(ext.getParsedValue());
                return aki.getKeyIdentifier();
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static String resolveDigestName(ASN1ObjectIdentifier oid) {
        if (OIWObjectIdentifiers.idSHA1.equals(oid)) return "SHA-1";
        if (NISTObjectIdentifiers.id_sha256.equals(oid)) return "SHA-256";
        if (NISTObjectIdentifiers.id_sha384.equals(oid)) return "SHA-384";
        if (NISTObjectIdentifiers.id_sha512.equals(oid)) return "SHA-512";
        return null;
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
        if (state == null || registeredSigners.isEmpty()) return -1;
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

    private record RegisteredSignerEntry(
        String keyLabel,
        PrivateKey privateKey,
        X509CertificateHolder[] chain,
        String algorithm,
        Instant notAfter,
        byte[] issuerEncoded,
        byte[] authorityKeyId,
        boolean preferred
    ) {}
}
