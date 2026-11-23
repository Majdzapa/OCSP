package com.company.incert.pkcs11j.crypto;

import com.company.incert.pkcs11j.Pkcs11Constants;
import com.company.incert.pkcs11j.Pkcs11Mechanism;
import com.company.incert.pkcs11j.port.Pkcs11LibraryPort;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Locale;

/**
 * ECDSA signing strategy ({@code SHA256withECDSA}, {@code SHA384withECDSA}, {@code SHA512withECDSA}).
 * Pre-hashes payload in the JVM, invokes {@code CKM_ECDSA}, and converts raw {@code r || s} to ASN.1 DER.
 */
public final class EcdsaSignatureStrategy implements SignatureStrategy {

    @Override
    public boolean supports(String signatureAlgorithm) {
        return signatureAlgorithm != null
                && signatureAlgorithm.toUpperCase(Locale.ROOT).contains("ECDSA");
    }

    @Override
    public byte[] sign(
            Pkcs11LibraryPort library,
            long session,
            long keyHandle,
            String signatureAlgorithm,
            byte[] data,
            boolean prehashInJvm) {
        byte[] digest = Pkcs11Digests.shaDigest(signatureAlgorithm, data);
        library.cSignInit(session, Pkcs11Mechanism.of(Pkcs11Constants.CKM_ECDSA), keyHandle);
        byte[] rawSig = library.cSign(session, digest);
        return rawEcdsaToDer(rawSig);
    }

    /** Converts fixed-width PKCS#11 ECDSA {@code r || s} output to X.509/OCSP ASN.1 DER sequence. */
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
}

