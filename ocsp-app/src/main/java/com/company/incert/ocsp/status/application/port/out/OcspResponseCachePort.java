package com.company.incert.ocsp.status.application.port.out;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface OcspResponseCachePort {

    Optional<byte[]> getResponse(String cacheKey);

    void saveResponse(String cacheKey, byte[] derResponse, Instant thisUpdate, Instant nextUpdate);

    void evict(String cacheKey);

    void evictAll();

    List<Map<String, Object>> getCacheEntries(int page, int size);

    long count();

    OcspResponseCachePort NOOP = new OcspResponseCachePort() {
        @Override public Optional<byte[]> getResponse(String cacheKey) { return Optional.empty(); }
        @Override public void saveResponse(String cacheKey, byte[] derResponse, Instant thisUpdate, Instant nextUpdate) {}
        @Override public void evict(String cacheKey) {}
        @Override public void evictAll() {}
        @Override public List<Map<String, Object>> getCacheEntries(int page, int size) { return List.of(); }
        @Override public long count() { return 0; }
    };
}

