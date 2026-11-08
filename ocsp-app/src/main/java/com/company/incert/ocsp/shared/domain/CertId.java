package com.company.incert.ocsp.shared.domain;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * Composite certificate identifier per RFC 6960.
 * Pure value object — no frameworks.
 */
public record CertId(
    byte[] issuerNameHash,
    byte[] issuerKeyHash,
    byte[] serialNumber
) {
    public CertId {
        issuerNameHash = issuerNameHash != null ? issuerNameHash.clone() : new byte[0];
        issuerKeyHash = issuerKeyHash != null ? issuerKeyHash.clone() : new byte[0];
        serialNumber = serialNumber != null ? serialNumber.clone() : new byte[0];
    }

    @Override
    public byte[] issuerNameHash() {
        return issuerNameHash.clone();
    }

    @Override
    public byte[] issuerKeyHash() {
        return issuerKeyHash.clone();
    }

    @Override
    public byte[] serialNumber() {
        return serialNumber.clone();
    }

    public String toHexKey() {
        HexFormat hex = HexFormat.of();
        return hex.formatHex(issuerNameHash) + ":" +
               hex.formatHex(issuerKeyHash) + ":" +
               hex.formatHex(serialNumber);
    }

    public String issuerKeyHashHex() {
        return HexFormat.of().formatHex(issuerKeyHash);
    }

    public String issuerNameHashHex() {
        return HexFormat.of().formatHex(issuerNameHash);
    }

    public String serialNumberHex() {
        return HexFormat.of().formatHex(serialNumber);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof CertId other)) return false;
        return Arrays.equals(issuerNameHash, other.issuerNameHash)
            && Arrays.equals(issuerKeyHash, other.issuerKeyHash)
            && Arrays.equals(serialNumber, other.serialNumber);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(issuerNameHash);
        result = 31 * result + Arrays.hashCode(issuerKeyHash);
        result = 31 * result + Arrays.hashCode(serialNumber);
        return result;
    }
}

