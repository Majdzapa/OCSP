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
        ASN1ObjectIdentifier curveOid = (keySize == 384)
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

