package com.company.incert.ocsp.status.adapter.out.jpa;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "ocsp_response_cache")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OcspResponseCacheJpaEntity {

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
