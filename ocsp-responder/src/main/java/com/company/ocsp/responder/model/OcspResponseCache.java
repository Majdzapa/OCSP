package com.company.ocsp.responder.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Shared (L2) cache of pre-signed OCSP responses, stored in MariaDB.
 *
 * <p>Cache key is {@code SHA-1(issuerNameHash || issuerKeyHash || serialNumber)}
 * represented as a 40-character hex string.
 *
 * <p>Rows are purged by a scheduled cleanup job once {@code nextUpdate} has elapsed.
 */
@Entity
@Table(
    name = "ocsp_response_cache",
    indexes = {
        @Index(name = "idx_next_update", columnList = "next_update")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OcspResponseCache {

    /**
     * Primary key — SHA-1 hex of CertID (40 chars).
     */
    @Id
    @Column(name = "cache_key", nullable = false, length = 40, columnDefinition = "CHAR(40)")
    private String cacheKey;

    /**
     * DER-encoded {@code OCSPResponse} bytes, ready to be written directly into
     * the HTTP response body.
     */
    @Lob
    @Column(name = "der_response", nullable = false, columnDefinition = "MEDIUMBLOB")
    private byte[] derResponse;

    @Column(name = "this_update", nullable = false)
    private Instant thisUpdate;

    /**
     * The point after which this cached response must not be served; drives both
     * expiry logic and the scheduled cleanup job.
     */
    @Column(name = "next_update", nullable = false)
    private Instant nextUpdate;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
