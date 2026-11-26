package lu.incert.ocsp.signing.pkcs11.crypto;

import lu.incert.ocsp.signing.pkcs11.Pkcs11Constants;
import lu.incert.ocsp.signing.pkcs11.Pkcs11LibraryPort;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Mechanism;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;

import java.util.List;

/**
 * PKCS#1 v1.5 RSA signing strategy ({@code SHA256withRSA}, {@code SHA384withRSA}, {@code SHA512withRSA}).
 */
public final class RsaPkcsSignatureStrategy implements SignatureStrategy {

    private static final List<String> ALGORITHMS = List.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA");

    @Override
    public String keyType() {
        return "RSA";
    }

    @Override
    public long pkcs11KeyType() {
        return Pkcs11Constants.CKK_RSA;
    }

    @Override
    public List<String> supportedAlgorithms() {
        return ALGORITHMS;
    }

    @Override
    public long requiredMechanism(String signatureAlgorithm, boolean prehashInJvm) {
        if (prehashInJvm) {
            return Pkcs11Constants.CKM_RSA_PKCS;
        }
        return switch (signatureAlgorithm) {
            case "SHA384withRSA" -> Pkcs11Constants.CKM_SHA384_RSA_PKCS;
            case "SHA512withRSA" -> Pkcs11Constants.CKM_SHA512_RSA_PKCS;
            default -> Pkcs11Constants.CKM_SHA256_RSA_PKCS;
        };
    }

    @Override
    public boolean supports(String signatureAlgorithm) {
        return "SHA256withRSA".equalsIgnoreCase(signatureAlgorithm)
                || "SHA384withRSA".equalsIgnoreCase(signatureAlgorithm)
                || "SHA512withRSA".equalsIgnoreCase(signatureAlgorithm);
    }

    @Override
    public byte[] sign(
            Pkcs11LibraryPort library,
            long session,
            long keyHandle,
            String signatureAlgorithm,
            byte[] data,
            boolean prehashInJvm) {
        if (prehashInJvm) {
            byte[] digestInfo = buildDigestInfo(signatureAlgorithm, data);
            library.cSignInit(session, Pkcs11Mechanism.of(Pkcs11Constants.CKM_RSA_PKCS), keyHandle);
            return library.cSign(session, digestInfo);
        }
        long mech = requiredMechanism(signatureAlgorithm, false);
        library.cSignInit(session, Pkcs11Mechanism.of(mech), keyHandle);
        return library.cSign(session, data);
    }

    private static byte[] buildDigestInfo(String alg, byte[] data) {
        ASN1ObjectIdentifier oid = switch (alg) {
            case "SHA384withRSA" -> NISTObjectIdentifiers.id_sha384;
            case "SHA512withRSA" -> NISTObjectIdentifiers.id_sha512;
            default -> NISTObjectIdentifiers.id_sha256;
        };
        byte[] digest = Pkcs11Digests.shaDigest(alg, data);
        try {
            return new DigestInfo(new AlgorithmIdentifier(oid, DERNull.INSTANCE), digest).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Failed encoding DigestInfo", e);
        }
    }
}

