package com.company.incert.pkcs11j.crypto;

import java.security.MessageDigest;

final class Pkcs11Digests {

    private Pkcs11Digests() {}

    static byte[] shaDigest(String alg, byte[] data) {
        String jcaAlg = switch (alg) {
            case "SHA384withECDSA", "SHA384withRSA" -> "SHA-384";
            case "SHA512withECDSA", "SHA512withRSA" -> "SHA-512";
            default -> "SHA-256";
        };
        try {
            return MessageDigest.getInstance(jcaAlg).digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("Digest algorithm unavailable: " + jcaAlg, e);
        }
    }
}

