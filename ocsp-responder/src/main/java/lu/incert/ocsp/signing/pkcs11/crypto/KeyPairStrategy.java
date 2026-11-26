package lu.incert.ocsp.signing.pkcs11.crypto;

import lu.incert.ocsp.signing.pkcs11.Pkcs11LibraryPort;

import java.util.List;

/**
 * Self-describing Open-Closed strategy for generating an asymmetric keypair on a PKCS#11 token.
 */
public interface KeyPairStrategy {

    /** Canonical key algorithm name (e.g. {@code RSA}, {@code EC}). */
    String keyAlgorithmName();

    /** Corresponding PKCS#11 {@code CKK_*} constant. */
    long pkcs11KeyType();

    /** PKCS#11 {@code CKM_*_KEY_PAIR_GEN} mechanism required on the HSM slot. */
    long keyPairGenMechanism();

    /** Supported key sizes / curves in bits (filtered further by live HSM {@code C_GetMechanismInfo}). */
    List<Integer> supportedKeySizes();

    boolean supports(String keyAlgorithm);

    String defaultSignatureAlgorithm();

    long[] generate(Pkcs11LibraryPort library, long session, String keyLabel, byte[] keyId, int keySize);
}

