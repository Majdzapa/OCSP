package com.company.ocsp.sync.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.time.Instant;

/**
 * Immutable DTO representing a KMS domain event received from RabbitMQ.
 *
 * <p>Conforms to the message contract defined in the architecture document
 * (Section 7.2).  Extra fields from future KMS versions are ignored
 * ({@link JsonIgnoreProperties}) to allow forward-compatible evolution.
 *
 * <p>Routing key determines the semantic:
 * <ul>
 *   <li>{@code cert.issued}   → {@code CertificateIssued}
 *   <li>{@code cert.revoked}  → {@code CertificateRevoked}
 *   <li>{@code cert.hold}     → {@code CertificateHeld}
 *   <li>{@code cert.unrevoked} → {@code CertificateUnrevoked}
 * </ul>
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertificateEventDto {

    /** Globally-unique event identifier from the KMS (idempotency key). */
    private String eventId;

    /** Event type: CertificateIssued | CertificateRevoked | CertificateHeld | CertificateUnrevoked. */
    private String eventType;

    /** Human-readable CA name (e.g. "Incert-Root-CA-01"). */
    private String issuedBy;

    /** Hex-encoded SHA-1 of the issuer DN (issuerNameHash per RFC 6960). */
    private String issuerNameHashHex;

    /** Hex-encoded SHA-1 of the issuer public key (issuerKeyHash per RFC 6960). */
    private String issuerKeyHashHex;

    /** Hex-encoded certificate serial number. */
    private String serialNumberHex;

    /** Time at which revocation took effect (null for issuance events). */
    private Instant revocationTime;

    /** RFC 5280 revocation reason string (e.g. "keyCompromise"), nullable. */
    private String revocationReason;

    /** Wall-clock time the event was emitted by the KMS. */
    private Instant occurredAt;
}
