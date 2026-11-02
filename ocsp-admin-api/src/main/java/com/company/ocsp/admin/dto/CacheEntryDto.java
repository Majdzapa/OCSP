package com.company.ocsp.admin.dto;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class CacheEntryDto {
    private String  cacheKey;
    private Instant thisUpdate;
    private Instant nextUpdate;
    private Instant createdAt;
    /** Size of the DER-encoded response in bytes. */
    private int     responseSizeBytes;
}
