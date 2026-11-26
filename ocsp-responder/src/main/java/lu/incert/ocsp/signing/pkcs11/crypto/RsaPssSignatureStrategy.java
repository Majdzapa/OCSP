package lu.incert.ocsp.signing.pkcs11.crypto;

import lu.incert.ocsp.signing.pkcs11.Pkcs11Constants;
import lu.incert.ocsp.signing.pkcs11.Pkcs11LibraryPort;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Mechanism;

import java.util.List;

/**
 * RSA-PSS signing strategy ({@code SHA256withRSAandMGF1}, {@code SHA384withRSAandMGF1}, {@code SHA512withRSAandMGF1})
 * using {@code CKM_SHA*_RSA_PKCS_PSS}.
 */
public final class RsaPssSignatureStrategy implements SignatureStrategy {

    private static final List<String> ALGORITHMS = List.of(
            "SHA256withRSAandMGF1",
            "SHA384withRSAandMGF1",
            "SHA512withRSAandMGF1"
    );

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
        if ("SHA384withRSAandMGF1".equalsIgnoreCase(signatureAlgorithm)) {
            return Pkcs11Constants.CKM_SHA384_RSA_PKCS_PSS;
        }
        if ("SHA512withRSAandMGF1".equalsIgnoreCase(signatureAlgorithm)) {
            return Pkcs11Constants.CKM_SHA512_RSA_PKCS_PSS;
        }
        return Pkcs11Constants.CKM_SHA256_RSA_PKCS_PSS;
    }

    @Override
    public boolean supports(String signatureAlgorithm) {
        return "SHA256withRSAandMGF1".equalsIgnoreCase(signatureAlgorithm)
                || "SHA384withRSAandMGF1".equalsIgnoreCase(signatureAlgorithm)
                || "SHA512withRSAandMGF1".equalsIgnoreCase(signatureAlgorithm);
    }

    @Override
    public byte[] sign(
            Pkcs11LibraryPort library,
            long session,
            long keyHandle,
            String signatureAlgorithm,
            byte[] data,
            boolean prehashInJvm) {
        Pkcs11Mechanism mech = "SHA384withRSAandMGF1".equalsIgnoreCase(signatureAlgorithm)
                ? Pkcs11Mechanism.rsaPssSha384()
                : "SHA512withRSAandMGF1".equalsIgnoreCase(signatureAlgorithm)
                        ? Pkcs11Mechanism.rsaPssSha512()
                        : Pkcs11Mechanism.rsaPssSha256();
        library.cSignInit(session, mech, keyHandle);
        return library.cSign(session, data);
    }
}

