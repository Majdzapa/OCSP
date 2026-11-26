package lu.incert.ocsp.signing.pkcs11.crypto;

import lu.incert.ocsp.signing.pkcs11.Pkcs11Attribute;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Constants;
import lu.incert.ocsp.signing.pkcs11.Pkcs11LibraryPort;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Mechanism;

import java.util.List;
import java.util.Locale;

/**
 * Generates non-extractable RSA (2048/3072/4096-bit) keypairs inside a PKCS#11 token.
 */
public final class RsaKeyPairStrategy implements KeyPairStrategy {

    private static final byte[] RSA_PUBLIC_EXPONENT = new byte[]{0x01, 0x00, 0x01};
    private static final List<Integer> SUPPORTED_KEY_SIZES = List.of(2048, 3072, 4096);

    @Override
    public String keyAlgorithmName() {
        return "RSA";
    }

    @Override
    public long pkcs11KeyType() {
        return Pkcs11Constants.CKK_RSA;
    }

    @Override
    public long keyPairGenMechanism() {
        return Pkcs11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN;
    }

    @Override
    public List<Integer> supportedKeySizes() {
        return SUPPORTED_KEY_SIZES;
    }

    @Override
    public boolean supports(String keyAlgorithm) {
        return keyAlgorithm != null && !keyAlgorithm.isBlank()
                && "RSA".equalsIgnoreCase(keyAlgorithm.trim().toUpperCase(Locale.ROOT));
    }

    @Override
    public String defaultSignatureAlgorithm() {
        return "SHA256withRSA";
    }

    @Override
    public long[] generate(Pkcs11LibraryPort library, long session, String keyLabel, byte[] keyId, int keySize) {
        if (!SUPPORTED_KEY_SIZES.contains(keySize)) {
            throw new IllegalArgumentException(
                    "Unsupported RSA key size: " + keySize + " bits. Supported sizes: " + SUPPORTED_KEY_SIZES);
        }
        int rsaBits = keySize;
        List<Pkcs11Attribute> pubTemplate = List.of(
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_TOKEN, true),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_VERIFY, true),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_ENCRYPT, false),
                Pkcs11Attribute.ofUlong(Pkcs11Constants.CKA_MODULUS_BITS, rsaBits),
                Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_PUBLIC_EXPONENT, RSA_PUBLIC_EXPONENT),
                Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, keyLabel),
                Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_ID, keyId)
        );
        List<Pkcs11Attribute> privTemplate = List.of(
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_TOKEN, true),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_PRIVATE, true),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_SENSITIVE, true),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_EXTRACTABLE, false),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_SIGN, true),
                Pkcs11Attribute.ofBool(Pkcs11Constants.CKA_DECRYPT, false),
                Pkcs11Attribute.ofString(Pkcs11Constants.CKA_LABEL, keyLabel),
                Pkcs11Attribute.ofBytes(Pkcs11Constants.CKA_ID, keyId)
        );
        return library.cGenerateKeyPair(
                session, Pkcs11Mechanism.of(Pkcs11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN), pubTemplate, privTemplate);
    }
}

