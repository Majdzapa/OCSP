package lu.incert.ocsp.signing.pkcs11.crypto;

import lu.incert.ocsp.signing.pkcs11.Pkcs11LibraryPort;

import java.util.List;

/**
 * Self-describing Open-Closed strategy for signing data with a private key handle inside a PKCS#11 token.
 */
public interface SignatureStrategy {

    /** Compatible canonical key algorithm ({@code RSA}, {@code EC}, etc.). */
    String keyType();

    /** Corresponding PKCS#11 {@code CKK_*} constant required on the private key handle. */
    long pkcs11KeyType();

    /** Canonical signature algorithm names implemented by this strategy. */
    List<String> supportedAlgorithms();

    /** PKCS#11 {@code CKM_*} mechanism required on the HSM slot for {@code signatureAlgorithm}. */
    long requiredMechanism(String signatureAlgorithm, boolean prehashInJvm);

    boolean supports(String signatureAlgorithm);

    byte[] sign(
            Pkcs11LibraryPort library,
            long session,
            long keyHandle,
            String signatureAlgorithm,
            byte[] data,
            boolean prehashInJvm
    );
}

