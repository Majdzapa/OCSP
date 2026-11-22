package com.company.incert.ocsp.usecase;

import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.util.HexFormat;

/**
 * Reusable use case for sanitizing and canonicalizing certificate serial numbers
 * and hex digests across OCSP CertID lookups, RabbitMQ event ingestion, and
 * Outbox/Inbox reconciliation.
 */
@Component
public class CanonicalizeSerialHexUseCase {

    private static final HexFormat HEX = HexFormat.of();

    /**
     * Parses a raw hex string (stripping colons/spaces and padding odd length) into raw bytes.
     */
    public static byte[] parseHexBytes(String rawHex) {
        if (rawHex == null) {
            throw new IllegalArgumentException("hex value is required");
        }
        String clean = rawHex.toLowerCase().replaceAll("[^0-9a-f]", "");
        if (clean.isEmpty()) {
            throw new IllegalArgumentException("hex value is empty");
        }
        if (clean.length() % 2 != 0) {
            clean = "0" + clean;
        }
        return HEX.parseHex(clean);
    }

    /**
     * Converts a raw serial number hex string into minimal two's-complement DER integer bytes
     * (matching {@link BigInteger#toByteArray()}, which is what RFC 6960 {@code CertID.getSerialNumber()} produces).
     */
    public static byte[] toCanonicalSerialBytes(String rawSerialHex) {
        return new BigInteger(1, parseHexBytes(rawSerialHex)).toByteArray();
    }

    /**
     * Converts a raw serial number hex string into a lowercase canonical hex representation
     * (or empty string if null/blank).
     */
    public static String toCanonicalSerialHex(String rawSerialHex) {
        if (rawSerialHex == null) {
            return "";
        }
        String clean = rawSerialHex.toLowerCase().replaceAll("[^0-9a-f]", "");
        if (clean.isEmpty()) {
            return "";
        }
        if (clean.length() % 2 != 0) {
            clean = "0" + clean;
        }
        return HEX.formatHex(new BigInteger(1, HEX.parseHex(clean)).toByteArray()).toLowerCase();
    }
}
