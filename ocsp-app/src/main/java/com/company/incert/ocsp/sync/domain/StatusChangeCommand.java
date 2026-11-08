package com.company.incert.ocsp.sync.domain;

import com.company.incert.ocsp.shared.domain.CertificateStatus;
import com.company.incert.ocsp.shared.domain.RevocationReason;

import java.time.Instant;
import java.util.Arrays;

/** Command object created from a Kafka CertificateStatusChanged event. */
public record StatusChangeCommand(
    String eventId,
    byte[] issuerNameHash,
    byte[] issuerKeyHash,
    byte[] serialNumber,
    CertificateStatus status,
    Instant revocationTime,
    RevocationReason revocationReason,
    Instant occurredAt,
    long sequence
) {
    public StatusChangeCommand {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof StatusChangeCommand that)) return false;
        return sequence == that.sequence
            && Arrays.equals(issuerNameHash, that.issuerNameHash)
            && Arrays.equals(issuerKeyHash, that.issuerKeyHash)
            && Arrays.equals(serialNumber, that.serialNumber)
            && java.util.Objects.equals(eventId, that.eventId)
            && status == that.status
            && java.util.Objects.equals(revocationTime, that.revocationTime)
            && revocationReason == that.revocationReason
            && java.util.Objects.equals(occurredAt, that.occurredAt);
    }

    @Override
    public int hashCode() {
        int result = java.util.Objects.hashCode(eventId);
        result = 31 * result + Arrays.hashCode(issuerNameHash);
        result = 31 * result + Arrays.hashCode(issuerKeyHash);
        result = 31 * result + Arrays.hashCode(serialNumber);
        result = 31 * result + java.util.Objects.hashCode(status);
        result = 31 * result + java.util.Objects.hashCode(revocationTime);
        result = 31 * result + java.util.Objects.hashCode(revocationReason);
        result = 31 * result + java.util.Objects.hashCode(occurredAt);
        result = 31 * result + Long.hashCode(sequence);
        return result;
    }
}

