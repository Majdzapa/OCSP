package com.company.incert.ocsp.signing.pkcs11;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Encapsulates PKCS#11 object enumeration, attribute reads, and decoding of token public keys into ASN.1 {@link SubjectPublicKeyInfo}.
 */
final class Pkcs11ObjectStore {

    private final Pkcs11LibraryPort library;

    Pkcs11ObjectStore(Pkcs11LibraryPort library) {
        this.library = library;
    }

    List<KeyMetadata> listPrivateKeys(long session) {
        long[] privHandles = findObjects(session, List.of(
                Pkcs11Attribute.ofUlong(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_PRIVATE_KEY)
        ));
        List<KeyMetadata> result = new ArrayList<>();
        for (long privHandle : privHandles) {
            String label = readStringAttribute(session, privHandle, Pkcs11Constants.CKA_LABEL).orElse(null);
            if (label == null || label.isBlank()) {
                continue;
            }
            long keyType = readUlongAttribute(session, privHandle, Pkcs11Constants.CKA_KEY_TYPE)
                    .orElse(Pkcs11Constants.CKK_RSA);
            String alg = keyType == Pkcs11Constants.CKK_EC ? "EC" : "RSA";
            int bits = resolveKeySizeBits(session, privHandle, label, keyType);
            result.add(new KeyMetadata(label, alg, bits, privHandle));
        }
        return result;
    }

    Optional<Long> findByClassAndLabel(long session, long objectClass, String label) {
        long[] handles = findObjects(session, List.of(
                Pkcs11Attribute.ofUlong(Pkcs11Constants.CKA_CLASS, objectClass),
                Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, label)
        ));
        return handles.length > 0 ? Optional.of(handles[0]) : Optional.empty();
    }

    SubjectPublicKeyInfo readPublicKey(long session, String keyLabel, String providerId) {
        Optional<Long> pubOpt = findByClassAndLabel(session, Pkcs11Constants.CKO_PUBLIC_KEY, keyLabel);
        if (pubOpt.isPresent()) {
            return extractSubjectPublicKeyInfo(session, pubOpt.get());
        }
        Optional<Long> certOpt = findByClassAndLabel(session, Pkcs11Constants.CKO_CERTIFICATE, keyLabel);
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
                "Public key or certificate not found for keyLabel='" + keyLabel + "' on provider '" + providerId + "'");
    }

    SubjectPublicKeyInfo extractSubjectPublicKeyInfo(long session, long pubKeyHandle) {
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
        long targetHandle = findByClassAndLabel(session, Pkcs11Constants.CKO_PUBLIC_KEY, label)
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

    private static byte[] unwrapEcPoint(byte[] raw) {
        if (raw == null || raw.length == 0) {
            throw new IllegalStateException("Empty CKA_EC_POINT attribute");
        }
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
            } catch (Exception ignored) {}
        }
        return raw;
    }
}

