package com.company.ocsp.responder.util;

import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility for computing the cache key from an RFC 6960 {@code CertID}.
 *
 * <p>Cache key = lowercase hex of SHA-1( issuerNameHash || issuerKeyHash || serialNumber ).
 * This gives a 40-character string suitable as a MariaDB {@code CHAR(40)} primary key
 * and a Caffeine cache key.
 */
public final class CertIdCacheKeyUtil {

    private CertIdCacheKeyUtil() {}

    /**
     * Computes the cache key from raw CertID byte arrays (as extracted from a
     * Bouncy Castle {@link CertID}).
     */
    public static String computeKey(byte[] issuerNameHash, byte[] issuerKeyHash, byte[] serialNumber) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(issuerNameHash);
            sha1.update(issuerKeyHash);
            sha1.update(serialNumber);
            return Hex.toHexString(sha1.digest());
        } catch (NoSuchAlgorithmException e) {
            // SHA-1 is guaranteed by the JVM specification
            throw new IllegalStateException("SHA-1 not available", e);
        }
    }
}
