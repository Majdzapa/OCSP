package com.company.ocsp.admin.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

/**
 * L2 OCSP response cache entry.
 *
 * <p>Read-only from the admin API's perspective.  Deletion (invalidation) is
 * performed directly via {@link OcspResponseCacheRepository#deleteById(Object)}.
 */
@Entity
@Table(name = "ocsp_response_cache")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OcspResponseCache {

    /** SHA-1 hex of the CertID (40 chars). */
    @Id
    @Column(name = "cache_key", nullable = false, length = 40, columnDefinition = "CHAR(40)")
    private String cacheKey;

    @Lob
    @Column(name = "der_response", nullable = false, columnDefinition = "MEDIUMBLOB")
    private byte[] derResponse;

    @Column(name = "this_update", nullable = false)
    private Instant thisUpdate;

    @Column(name = "next_update", nullable = false)
    private Instant nextUpdate;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}
