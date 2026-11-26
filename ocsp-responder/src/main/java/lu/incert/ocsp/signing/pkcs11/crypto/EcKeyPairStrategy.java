package lu.incert.ocsp.signing.pkcs11.crypto;

import lu.incert.ocsp.signing.pkcs11.Pkcs11Attribute;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Constants;
import lu.incert.ocsp.signing.pkcs11.Pkcs11LibraryPort;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Mechanism;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.util.List;

/**
 * Generates non-extractable ECDSA (P-256 / P-384) keypairs inside a PKCS#11 token.
 */
public final class EcKeyPairStrategy implements KeyPairStrategy {

    private static final List<Integer> SUPPORTED_KEY_SIZES = List.of(256, 384, 521);

    @Override
    public String keyAlgorithmName() {
        return "EC";
    }

    @Override
    public long pkcs11KeyType() {
        return Pkcs11Constants.CKK_EC;
    }

    @Override
    public long keyPairGenMechanism() {
        return Pkcs11Constants.CKM_EC_KEY_PAIR_GEN;
    }

    @Override
    public List<Integer> supportedKeySizes() {
        return SUPPORTED_KEY_SIZES;
    }

    @Override
    public boolean supports(String keyAlgorithm) {
        if (keyAlgorithm == null) {
            return false;
        }
        String norm = keyAlgorithm.trim().toUpperCase();
        return "EC".equals(norm) || "ECDSA".equals(norm);
    }

    @Override
    public String defaultSignatureAlgorithm() {
        return "SHA256withECDSA";
    }

    @Override
    public long[] generate(Pkcs11LibraryPort library, long session, String keyLabel, byte[] keyId, int keySize) {
        ASN1ObjectIdentifier curveOid = switch (keySize) {
            case 256 -> X9ObjectIdentifiers.prime256v1;
            case 384 -> SECObjectIdentifiers.secp384r1;
            case 521 -> SECObjectIdentifiers.secp521r1;
            default -> throw new IllegalArgumentException(
                    "Unsupported EC curve size: " + keySize + " bits. Supported curves: " + SUPPORTED_KEY_SIZES);
        };
        byte[] ecParamsDer;
        try {
            ecParamsDer = curveOid.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode EC curve OID", e);
        }

        List<Pkcs11Attribute> pubTemplate = List.of(
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_TOKEN, true),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_VERIFY, true),
                Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, keyLabel),
                Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_ID, keyId),
                Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_EC_PARAMS, ecParamsDer)
        );
        List<Pkcs11Attribute> privTemplate = List.of(
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_TOKEN, true),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_PRIVATE, true),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_SENSITIVE, true),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_EXTRACTABLE, false),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_SIGN, true),
                Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, keyLabel),
                Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_ID, keyId)
        );
        return library.cGenerateKeyPair(
                session, Pkcs11Mechanism.of(Pkcs11Constants.CKM_EC_KEY_PAIR_GEN), pubTemplate, privTemplate);
    }
}

