package com.company.ocsp.responder.cache;

import com.company.ocsp.responder.model.OcspResponseCache;
import com.company.ocsp.responder.repository.OcspResponseCacheRepository;
import com.github.benmanes.caffeine.cache.Cache;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;

/**
 * Two-layer status/response cache abstraction.
 *
 * <ul>
 *   <li><b>L1 (Caffeine)</b> — per-JVM, sub-millisecond, bounded, auto-expires.
 *   <li><b>L2 (MariaDB)</b> — shared across the responder fleet, survives restarts.
 * </ul>
 *
 * <p>On a cache miss at L1, the implementation falls through to L2.  If L2 also misses,
 * the caller is responsible for building and signing a new response and then calling
 * {@link #put(String, byte[], Instant, Instant)} to populate both layers.
 *
 * <p>Explicit eviction (e.g., triggered by a {@code StatusChanged} RabbitMQ message
 * or a manual operator action from the React console) removes the entry from both layers.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OcspResponseCacheManager {

    private final Cache<String, byte[]> caffeineL1Cache;
    private final OcspResponseCacheRepository l2Repository;
    private final MeterRegistry meterRegistry;

    /**
     * Looks up a pre-signed OCSP response from L1 then L2.
     *
     * @param cacheKey SHA-1 hex of the CertID
     * @return DER-encoded OCSPResponse bytes, or empty if not cached / expired
     */
    public Optional<byte[]> get(String cacheKey) {
        // --- L1 lookup ---
        byte[] l1Result = caffeineL1Cache.getIfPresent(cacheKey);
        if (l1Result != null) {
            meterRegistry.counter("ocsp.cache.hit", "layer", "l1").increment();
            log.debug("L1 cache hit for key={}", cacheKey);
            return Optional.of(l1Result);
        }

        // --- L2 lookup ---
        Optional<OcspResponseCache> l2Result = l2Repository.findValidByCacheKey(cacheKey, Instant.now());
        if (l2Result.isPresent()) {
            meterRegistry.counter("ocsp.cache.hit", "layer", "l2").increment();
            log.debug("L2 cache hit for key={}", cacheKey);
            byte[] der = l2Result.get().getDerResponse();
            // Warm L1 so subsequent requests don't hit the DB
            caffeineL1Cache.put(cacheKey, der);
            return Optional.of(der);
        }

        meterRegistry.counter("ocsp.cache.miss").increment();
        log.debug("Cache miss for key={}", cacheKey);
        return Optional.empty();
    }

    /**
     * Stores a signed OCSP response in both L1 and L2.
     *
     * @param cacheKey   SHA-1 hex of the CertID
     * @param derBytes   DER-encoded OCSPResponse
     * @param thisUpdate thisUpdate timestamp embedded in the response
     * @param nextUpdate nextUpdate timestamp embedded in the response
     */
    public void put(String cacheKey, byte[] derBytes, Instant thisUpdate, Instant nextUpdate) {
        // L1
        caffeineL1Cache.put(cacheKey, derBytes);

        // L2
        OcspResponseCache entry = OcspResponseCache.builder()
            .cacheKey(cacheKey)
            .derResponse(derBytes)
            .thisUpdate(thisUpdate)
            .nextUpdate(nextUpdate)
            .createdAt(Instant.now())
            .build();
        l2Repository.save(entry);

        log.debug("Cached OCSP response for key={}, nextUpdate={}", cacheKey, nextUpdate);
    }

    /**
     * Explicitly evicts an entry from both L1 and L2.
     * Called on receipt of a {@code StatusChanged} invalidation message or
     * a manual operator invalidation from the admin console.
     *
     * @param cacheKey SHA-1 hex of the CertID to evict
     */
    public void evict(String cacheKey) {
        caffeineL1Cache.invalidate(cacheKey);
        l2Repository.deleteById(cacheKey);
        log.info("Evicted cache entry for key={}", cacheKey);
        meterRegistry.counter("ocsp.cache.eviction").increment();
    }
}
