package com.company.incert.ocsp.signing.pkcs11.crypto;

import com.company.incert.ocsp.signing.pkcs11.Pkcs11Attribute;
import com.company.incert.ocsp.signing.pkcs11.Pkcs11Constants;
import com.company.incert.ocsp.signing.pkcs11.Pkcs11LibraryPort;
import com.company.incert.ocsp.signing.pkcs11.Pkcs11Mechanism;

import java.util.List;
import java.util.Locale;

/**
 * Generates non-extractable RSA (2048/3072/4096-bit) keypairs inside a PKCS#11 token.
 */
public final class RsaKeyPairStrategy implements KeyPairStrategy {

    private static final byte[] RSA_PUBLIC_EXPONENT = new byte[]{0x01, 0x00, 0x01};

    @Override
    public boolean supports(String keyAlgorithm) {
        return keyAlgorithm == null || keyAlgorithm.isBlank()
                || "RSA".equalsIgnoreCase(keyAlgorithm.trim().toUpperCase(Locale.ROOT));
    }

    @Override
    public String defaultSignatureAlgorithm() {
        return "SHA256withRSA";
    }

    @Override
    public long[] generate(Pkcs11LibraryPort library, long session, String keyLabel, byte[] keyId, int keySize) {
        int rsaBits = (keySize == 2048 || keySize == 3072 || keySize == 4096) ? keySize : 3072;
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

