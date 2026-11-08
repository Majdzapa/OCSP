package com.company.incert.ocsp.status.adapter.out.cache;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.status.application.port.out.CacheEvictor;
import com.company.incert.ocsp.status.application.port.out.StatusLookup;
import com.company.incert.ocsp.shared.CertificateStatusRecord;
import com.github.benmanes.caffeine.cache.Cache;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

/**
 * L1 Caffeine-backed status cache adapter.
 * Implements StatusLookup (read) and CacheEvictor (invalidation).
 */
@Slf4j
@RequiredArgsConstructor
public class CaffeineStatusCacheAdapter implements StatusLookup, CacheEvictor {

    private final Cache<String, CertificateStatusRecord> caffeineCache;

    @Override
    public Optional<CertificateStatusRecord> findStatus(CertId certId) {
        CertificateStatusRecord cached = caffeineCache.getIfPresent(certId.toHexKey());
        if (cached != null) {
            log.debug("L1 cache hit for key={}", certId.toHexKey());
        }
        return Optional.ofNullable(cached);
    }

    public void put(CertId certId, CertificateStatusRecord record) {
        caffeineCache.put(certId.toHexKey(), record);
    }

    @Override
    public void evict(CertId certId) {
        caffeineCache.invalidate(certId.toHexKey());
        log.debug("Evicted cache for key={}", certId.toHexKey());
    }

    @Override
    public void evictAll() {
        caffeineCache.invalidateAll();
        log.info("Evicted all entries from L1 status cache");
    }
}
