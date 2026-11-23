package com.company.incert.pkcs11j.provider;

import com.company.incert.pkcs11j.KeyMetadata;
import com.company.incert.pkcs11j.Pkcs11Attribute;
import com.company.incert.pkcs11j.Pkcs11Constants;
import com.company.incert.pkcs11j.Pkcs11Exception;
import com.company.incert.pkcs11j.Pkcs11Mechanism;
import com.company.incert.pkcs11j.TokenInfo;
import com.company.incert.pkcs11j.port.Pkcs11LibraryPort;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * High-level PKCS#11 device facade for a single configured HSM slot/token, backed by
 * {@link Pkcs11LibraryPort} and a bounded {@link Pkcs11SessionPool}.
 */
public final class Pkcs11Provider implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11Provider.class);
    private static final byte[] RSA_PUBLIC_EXPONENT = new byte[]{0x01, 0x00, 0x01}; // 65537

    private final Pkcs11ProviderConfig config;
    private final Pkcs11LibraryPort library;
    private final long slotId;
    private final TokenInfo initialTokenInfo;
    private final Pkcs11SessionPool sessionPool;
    private final Runnable onCloseCallback;

    Pkcs11Provider(Pkcs11ProviderConfig config, Pkcs11LibraryPort library, Runnable onCloseCallback) {
        this.config = config;
        this.library = library;
        this.onCloseCallback = onCloseCallback;

        TokenResolution resolved = resolveSlot(library, config);
        this.slotId = resolved.slotId();
        this.initialTokenInfo = resolved.tokenInfo();
        this.sessionPool = new Pkcs11SessionPool(library, slotId, config.pinCopy(), config.poolSize());
        log.info("Registered PKCS11J provider '{}' (library={}, token='{}', slotId={}, poolSize={})",
                config.providerId(), config.libraryPath(), initialTokenInfo.label(), slotId, config.poolSize());
    }

    public String getProviderId() {
        return config.providerId();
    }

    public String getLibraryPath() {
        return config.libraryPath();
    }

    public String getTokenLabel() {
        return initialTokenInfo.label();
    }

    public long getSlotId() {
        return slotId;
    }

    public TokenInfo getTokenInfo() {
        return library.cGetTokenInfo(slotId);
    }

    public List<KeyMetadata> listKeys() {
        return sessionPool.withSession(session -> {
            long[] privHandles = findObjects(session, List.of(
                    Pkcs11Attribute.ofUlong(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PRIVATE_KEY)
            ));
            List<KeyMetadata> result = new ArrayList<>();
            for (long privHandle : privHandles) {
                String label = readStringAttribute(session, privHandle, Pkcs11Constants.CKA_LABEL).orElse(null);
                if (label == null || label.isBlank()) {
                    continue;
                }
                long keyType = readUlongAttribute(session, privHandle, Pkcs11Constants.CKA_KEY_TYPE).orElse(Pkcs11Constants.CKK_RSA);
                String alg = keyType == Pkcs11Constants.CKK_EC ? "EC" : "RSA";
                int bits = resolveKeySizeBits(session, privHandle, label, keyType);
                result.add(new KeyMetadata(label, alg, bits, privHandle));
            }
            return result;
        });
    }

    public List<String> listKeyLabels() {
        return listKeys().stream()
                .map(KeyMetadata::keyLabel)
                .distinct()
                .toList();
    }

    public SubjectPublicKeyInfo generateKeyPair(String keyLabel, String keyAlgorithm, int keySize) {
        if (keyLabel == null || keyLabel.isBlank()) {
            throw new IllegalArgumentException("keyLabel must not be blank");
        }
        String cleanLabel = keyLabel.trim();
        String alg = (keyAlgorithm != null && !keyAlgorithm.isBlank())
                ? keyAlgorithm.trim().toUpperCase(Locale.ROOT)
                : "RSA";

        return sessionPool.withRwSession(session -> {
            if (findObjectByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel).isPresent()) {
                throw new IllegalArgumentException(
                        "Key label '" + cleanLabel + "' already exists on provider '" + config.providerId() + "'");
            }
            byte[] keyId = cleanLabel.getBytes(StandardCharsets.UTF_8);

            if ("EC".equals(alg) || "ECDSA".equals(alg)) {
                int ecBits = (keySize == 384) ? 384 : 256;
                ASN1ObjectIdentifier curveOid = (ecBits == 384)
                        ? SECObjectIdentifiers.secp384r1
                        : X9ObjectIdentifiers.prime256v1;
                byte[] ecParamsDer;
                try {
                    ecParamsDer = curveOid.getEncoded();
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to encode EC curve OID", e);
                }

                List<Pkcs11Attribute> pubTemplate = List.of(
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_TOKEN, true),
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_VERIFY, true),
                        Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, cleanLabel),
                        Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_ID, keyId),
                        Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_EC_PARAMS, ecParamsDer)
                );
                List<Pkcs11Attribute> privTemplate = List.of(
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_TOKEN, true),
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_PRIVATE, true),
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_SENSITIVE, true),
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_EXTRACTABLE, false),
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_SIGN, true),
                        Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, cleanLabel),
                        Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_ID, keyId)
                );

                long[] pair = library.cGenerateKeyPair(
                        session,
                        Pkcs11Mechanism.of(Pkcs11Constants.CKM_EC_KEY_PAIR_GEN),
                        pubTemplate,
                        privTemplate);
                log.info("Generated EC P-{} keypair '{}' on provider '{}' (pubHandle={}, privHandle={})",
                        ecBits, cleanLabel, config.providerId(), pair[0], pair[1]);
                return extractSubjectPublicKeyInfo(session, pair[0]);
            }

            int rsaBits = (keySize == 2048 || keySize == 3072 || keySize == 4096) ? keySize : 3072;
            List<Pkcs11Attribute> pubTemplate = List.of(
                    Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_TOKEN, true),
                    Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_VERIFY, true),
                    Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_ENCRYPT, false),
                    Pkcs11Attribute.ofUlong(Pkcs11Constants.CKA_MODULUS_BITS, rsaBits),
                    Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_PUBLIC_EXPONENT, RSA_PUBLIC_EXPONENT),
                    Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, cleanLabel),
                    Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_ID, keyId)
            );
            List<Pkcs11Attribute> privTemplate = List.of(
                    Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_TOKEN, true),
                    Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_PRIVATE, true),
                    Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_SENSITIVE, true),
                    Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_EXTRACTABLE, false),
                    Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_SIGN, true),
                    Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_DECRYPT, false),
                    Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, cleanLabel),
                    Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_ID, keyId)
            );

            long[] pair = library.cGenerateKeyPair(
                    session,
                    Pkcs11Mechanism.of(Pkcs11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN),
                    pubTemplate,
                    privTemplate);
            log.info("Generated RSA-{} keypair '{}' on provider '{}' (pubHandle={}, privHandle={})",
                    rsaBits, cleanLabel, config.providerId(), pair[0], pair[1]);
            return extractSubjectPublicKeyInfo(session, pair[0]);
        });
    }

    public SubjectPublicKeyInfo getPublicKey(String keyLabel) {
        return sessionPool.withSession(session -> {
            Optional<Long> pubOpt = findObjectByClassAndLabel(session, Pkcs11Constants.CKO_PUBLIC_KEY, keyLabel);
            if (pubOpt.isPresent()) {
                return extractSubjectPublicKeyInfo(session, pubOpt.get());
            }
            Optional<Long> certOpt = findObjectByClassAndLabel(session, Pkcs11Constants.CKO_CERTIFICATE, keyLabel);
            if (certOpt.isPresent()) {
                byte[] der = library.cGetAttributeValue(session, certOpt.get(), Pkcs11Constants.CKA_VALUE);
                if (der != null && der.length > 0) {
                    try {
                        return new X509CertificateHolder(der).getSubjectPublicKeyInfo();
                    } catch (Exception e) {
                        throw new IllegalStateException("Failed to decode certificate public key for '" + keyLabel + "'", e);
                    }
                }
            }
            throw new IllegalStateException(
                    "Public key or certificate not found for keyLabel='" + keyLabel + "' on provider '" + config.providerId() + "'");
        });
    }

    public String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
        if (keyLabel == null || keyLabel.isBlank()) {
            throw new IllegalArgumentException("Key label is required");
        }
        if (subjectDn == null || subjectDn.isBlank()) {
            throw new IllegalArgumentException("Subject DN is required");
        }
        String cleanLabel = keyLabel.trim();
        String cleanDn = subjectDn.trim();

        SubjectPublicKeyInfo spki;
        String sigAlg;

        if (reuseExistingKey) {
            spki = sessionPool.withSession(session -> {
                if (findObjectByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel).isEmpty()) {
                    throw new IllegalArgumentException(
                            "Existing private key '" + cleanLabel + "' not found on provider '" + config.providerId() + "'");
                }
                return null;
            });
            spki = getPublicKey(cleanLabel);
            boolean isEc = X9ObjectIdentifiers.id_ecPublicKey.equals(spki.getAlgorithm().getAlgorithm());
            sigAlg = isEc ? "SHA256withECDSA" : "SHA256withRSA";
        } else {
            String alg = (keyAlgorithm != null && !keyAlgorithm.isBlank()) ? keyAlgorithm.trim().toUpperCase(Locale.ROOT) : "RSA";
            spki = generateKeyPair(cleanLabel, alg, keySize);
            sigAlg = ("EC".equals(alg) || "ECDSA".equals(alg)) ? "SHA256withECDSA" : "SHA256withRSA";
        }

        try {
            PKCS10CertificationRequest csr = new PKCS10CertificationRequestBuilder(new X500Name(cleanDn), spki)
                    .build(new Pkcs11ContentSigner(this, cleanLabel, sigAlg));

            try (StringWriter sw = new StringWriter(); JcaPEMWriter pw = new JcaPEMWriter(sw)) {
                pw.writeObject(csr);
                pw.flush();
                return sw.toString();
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build PKCS#10 CSR for '" + cleanLabel + "': " + e.getMessage(), e);
        }
    }

    public void importCertificate(String keyLabel, X509CertificateHolder certHolder) {
        if (keyLabel == null || keyLabel.isBlank() || certHolder == null) {
            throw new IllegalArgumentException("keyLabel and certificate are required");
        }
        String cleanLabel = keyLabel.trim();

        sessionPool.withRwSession(session -> {
            if (findObjectByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel).isEmpty()) {
                throw new IllegalArgumentException(
                        "Private key '" + cleanLabel + "' not found on provider '" + config.providerId() + "'");
            }

            Optional<Long> existingPub = findObjectByClassAndLabel(session, Pkcs11Constants.CKO_PUBLIC_KEY, cleanLabel);
            if (existingPub.isPresent()) {
                SubjectPublicKeyInfo tokenSpki = extractSubjectPublicKeyInfo(session, existingPub.get());
                try {
                    if (!Arrays.equals(tokenSpki.getEncoded(), certHolder.getSubjectPublicKeyInfo().getEncoded())) {
                        throw new IllegalArgumentException(
                                "Imported certificate public key does not match private key '" + cleanLabel + "'");
                    }
                } catch (IllegalArgumentException e) {
                    throw e;
                } catch (Exception e) {
                    throw new IllegalStateException("Failed comparing certificate public key", e);
                }
            }

            try {
                byte[] certDer = certHolder.getEncoded();
                byte[] subjectDer = certHolder.getSubject().getEncoded();
                byte[] keyId = cleanLabel.getBytes(StandardCharsets.UTF_8);

                List<Pkcs11Attribute> template = List.of(
                        Pkcs11Attribute.ofUlong(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_CERTIFICATE),
                        Pkcs11Attribute.ofUlong(Pkcs11Constants.CKA_CERTIFICATE_TYPE, Pkcs11Constants.CKC_X_509),
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_TOKEN, true),
                        Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_PRIVATE, false),
                        Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, cleanLabel),
                        Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_ID, keyId),
                        Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_SUBJECT, subjectDer),
                        Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_VALUE, certDer)
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
        if (keyLabel == null || keyLabel.isBlank()) {
            throw new IllegalArgumentException("keyLabel must not be blank");
        }
        String cleanLabel = keyLabel.trim();
        String alg = signatureAlgorithm != null ? signatureAlgorithm.trim() : "SHA256withRSA";

        return sessionPool.withSession(session -> {
            long keyHandle = findObjectByClassAndLabel(session, Pkcs11Constants.CKO_PRIVATE_KEY, cleanLabel)
                    .orElseThrow(() -> new IllegalStateException(
                            "Private key '" + cleanLabel + "' not found on provider '" + config.providerId() + "'"));

            if (isEcdsa(alg)) {
                byte[] digest = digestForAlgorithm(alg, data);
                library.cSignInit(session, Pkcs11Mechanism.of(Pkcs11Constants.CKM_ECDSA), keyHandle);
                byte[] rawSig = library.cSign(session, digest);
                return rawEcdsaToDer(rawSig);
            }

            if ("SHA256withRSAandMGF1".equalsIgnoreCase(alg)) {
                library.cSignInit(session, Pkcs11Mechanism.rsaPssSha256(), keyHandle);
                return library.cSign(session, data);
            }

            if (config.prehashInJvm()) {
                byte[] digestInfoDer = buildRsaDigestInfo(alg, data);
                library.cSignInit(session, Pkcs11Mechanism.of(Pkcs11Constants.CKM_RSA_PKCS), keyHandle);
                return library.cSign(session, digestInfoDer);
            }

            long mech = switch (alg) {
                case "SHA384withRSA" -> Pkcs11Constants.CKM_SHA384_RSA_PKCS;
                case "SHA512withRSA" -> Pkcs11Constants.CKM_SHA512_RSA_PKCS;
                default -> Pkcs11Constants.CKM_SHA256_RSA_PKCS;
            };
            library.cSignInit(session, Pkcs11Mechanism.of(mech), keyHandle);
            return library.cSign(session, data);
        });
    }

    public Pkcs11ContentSigner createContentSigner(String keyLabel, String signatureAlgorithm) {
        return new Pkcs11ContentSigner(this, keyLabel, signatureAlgorithm);
    }

    public String healthCheck() {
        TokenInfo info = library.cGetTokenInfo(slotId);
        return "UP (token=" + info.label() + ", slotId=" + slotId + ", poolAvailable=" + sessionPool.availableSessions() + ")";
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

    private static TokenResolution resolveSlot(Pkcs11LibraryPort library, Pkcs11ProviderConfig config) {
        if (config.slotId() != null) {
            TokenInfo info = library.cGetTokenInfo(config.slotId());
            return new TokenResolution(config.slotId(), info);
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

    private Optional<Long> findObjectByClassAndLabel(long session, long objectClass, String label) {
        long[] handles = findObjects(session, List.of(
                Pkcs11Attribute.ofUlong(Pkcs11Constants.CKA_CLASS, objectClass),
                Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, label)
        ));
        return handles.length > 0 ? Optional.of(handles[0]) : Optional.empty();
    }

    private long[] findObjects(long session, List<Pkcs11Attribute> template) {
        library.cFindObjectsInit(session, template);
        try {
            List<Long> all = new ArrayList<>();
            while (true) {
                long[] batch = library.cFindObjects(session, 64);
                if (batch == null || batch.length == 0) {
                    break;
                }
                for (long h : batch) {
                    all.add(h);
                }
                if (batch.length < 64) {
                    break;
                }
            }
            long[] out = new long[all.size()];
            for (int i = 0; i < all.size(); i++) {
                out[i] = all.get(i);
            }
            return out;
        } finally {
            library.cFindObjectsFinal(session);
        }
    }

    private Optional<String> readStringAttribute(long session, long objectHandle, long attrType) {
        try {
            byte[] bytes = library.cGetAttributeValue(session, objectHandle, attrType);
            if (bytes == null || bytes.length == 0) {
                return Optional.empty();
            }
            return Optional.of(new String(bytes, StandardCharsets.UTF_8).trim());
        } catch (Pkcs11Exception e) {
            return Optional.empty();
        }
    }

    private Optional<Long> readUlongAttribute(long session, long objectHandle, long attrType) {
        try {
            return Optional.of(library.cGetAttributeUlong(session, objectHandle, attrType));
        } catch (Pkcs11Exception e) {
            return Optional.empty();
        }
    }

    private int resolveKeySizeBits(long session, long privHandle, String label, long keyType) {
        long targetHandle = findObjectByClassAndLabel(session, Pkcs11Constants.CKO_PUBLIC_KEY, label)
                .orElse(privHandle);
        try {
            if (keyType == Pkcs11Constants.CKK_EC) {
                byte[] ecParams = library.cGetAttributeValue(session, targetHandle, Pkcs11Constants.CKA_EC_PARAMS);
                if (ecParams != null && ecParams.length > 0) {
                    ASN1Primitive obj = ASN1Primitive.fromByteArray(ecParams);
                    if (SECObjectIdentifiers.secp384r1.equals(obj)) {
                        return 384;
                    }
                    if (SECObjectIdentifiers.secp521r1.equals(obj)) {
                        return 521;
                    }
                    return 256;
                }
                return 256;
            }
            byte[] modulus = library.cGetAttributeValue(session, targetHandle, Pkcs11Constants.CKA_MODULUS);
            if (modulus != null && modulus.length > 0) {
                return new BigInteger(1, modulus).bitLength();
            }
        } catch (Exception ignored) {}
        return keyType == Pkcs11Constants.CKK_EC ? 256 : 2048;
    }

    private SubjectPublicKeyInfo extractSubjectPublicKeyInfo(long session, long pubKeyHandle) {
        long keyType = library.cGetAttributeUlong(session, pubKeyHandle, Pkcs11Constants.CKA_KEY_TYPE);
        if (keyType == Pkcs11Constants.CKK_EC) {
            byte[] ecParams = library.cGetAttributeValue(session, pubKeyHandle, Pkcs11Constants.CKA_EC_PARAMS);
            byte[] ecPointRaw = library.cGetAttributeValue(session, pubKeyHandle, Pkcs11Constants.CKA_EC_POINT);
            try {
                ASN1Primitive paramsAsn1 = ASN1Primitive.fromByteArray(ecParams);
                byte[] pointBytes = unwrapEcPoint(ecPointRaw);
                return new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, paramsAsn1),
                        pointBytes);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to decode EC public key from token", e);
            }
        }
        byte[] modulusBytes = library.cGetAttributeValue(session, pubKeyHandle, Pkcs11Constants.CKA_MODULUS);
        byte[] exponentBytes = library.cGetAttributeValue(session, pubKeyHandle, Pkcs11Constants.CKA_PUBLIC_EXPONENT);
        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger exponent = new BigInteger(1, exponentBytes);
        try {
            return new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                    new org.bouncycastle.asn1.pkcs.RSAPublicKey(modulus, exponent));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode RSA public key from token", e);
        }
    }

    private static byte[] unwrapEcPoint(byte[] raw) throws Exception {
        if (raw == null || raw.length == 0) {
            throw new IllegalStateException("Empty CKA_EC_POINT attribute");
        }
        // PKCS#11 CKA_EC_POINT is typically a DER OCTET STRING wrapping 0x04 || X || Y (67 bytes for P-256, 99 for P-384).
        if (raw[0] == 0x04 && raw.length > 2) {
            try {
                ASN1Primitive parsed = ASN1Primitive.fromByteArray(raw);
                if (parsed instanceof ASN1OctetString oct) {
                    byte[] inner = oct.getOctets();
                    if (inner.length > 0 && inner[0] == 0x04
                            && (inner.length == 65 || inner.length == 97 || inner.length == 133)) {
                        return inner;
                    }
                }
            } catch (Exception ignored) {
                // fall through and return raw uncompressed point
            }
        }
        return raw;
    }

    private static boolean isEcdsa(String alg) {
        return alg.toUpperCase(Locale.ROOT).contains("ECDSA");
    }

    private static byte[] digestForAlgorithm(String alg, byte[] data) {
        String jcaAlg = switch (alg) {
            case "SHA384withECDSA", "SHA384withRSA" -> "SHA-384";
            case "SHA512withECDSA", "SHA512withRSA" -> "SHA-512";
            default -> "SHA-256";
        };
        try {
            return MessageDigest.getInstance(jcaAlg).digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("Digest algorithm unavailable: " + jcaAlg, e);
        }
    }

    private static byte[] buildRsaDigestInfo(String alg, byte[] data) {
        ASN1ObjectIdentifier digestOid = switch (alg) {
            case "SHA384withRSA" -> NISTObjectIdentifiers.id_sha384;
            case "SHA512withRSA" -> NISTObjectIdentifiers.id_sha512;
            default -> NISTObjectIdentifiers.id_sha256;
        };
        byte[] digest = digestForAlgorithm(alg, data);
        try {
            return new DigestInfo(new AlgorithmIdentifier(digestOid, DERNull.INSTANCE), digest).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed encoding DigestInfo", e);
        }
    }

    /**
     * Converts raw PKCS#11 ECDSA signature (fixed-width {@code r || s}) into X.509/OCSP ASN.1 DER
     * {@code SEQUENCE { INTEGER r, INTEGER s }}.
     */
    public static byte[] rawEcdsaToDer(byte[] rawSig) {
        if (rawSig == null || rawSig.length == 0 || rawSig.length % 2 != 0) {
            throw new IllegalArgumentException("Invalid raw ECDSA signature length: " + (rawSig == null ? 0 : rawSig.length));
        }
        int half = rawSig.length / 2;
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rawSig, 0, half));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rawSig, half, rawSig.length));
        try {
            ASN1EncodableVector v = new ASN1EncodableVector(2);
            v.add(new ASN1Integer(r));
            v.add(new ASN1Integer(s));
            return new DERSequence(v).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to DER-encode ECDSA signature", e);
        }
    }

    private record TokenResolution(long slotId, TokenInfo tokenInfo) {}
}
