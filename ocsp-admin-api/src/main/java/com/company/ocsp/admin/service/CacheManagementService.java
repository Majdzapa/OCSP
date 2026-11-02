package com.company.ocsp.admin.service;

import com.company.ocsp.admin.dto.CacheEntryDto;
import com.company.ocsp.admin.model.OcspResponseCache;
import com.company.ocsp.admin.repository.OcspResponseCacheRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

/**
 * Service for L2 cache inspection and manual invalidation from the admin console.
 *
 * <p>Reads and deletes entries in the {@code ocsp_response_cache} table.
 * After deleting from the DB, publishes a cache-invalidation signal to RabbitMQ
 * so all responder nodes immediately evict the entry from their Caffeine L1 caches.
 *
 * <p>The operator identity (extracted from the JWT subject claim) is included in
 * the audit log so every cache invalidation is fully traceable.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CacheManagementService {

    private final OcspResponseCacheRepository cacheRepository;
    private final RabbitTemplate              rabbitTemplate;

    @Value("${ocsp.rabbitmq.cache-invalidation-exchange:ocsp.internal}")
    private String cacheInvalidationExchange;

    @Value("${ocsp.rabbitmq.cache-invalidation-routing-key:ocsp.cache.invalidate}")
    private String cacheInvalidationRoutingKey;

    // -------------------------------------------------------------------------
    // Read
    // -------------------------------------------------------------------------

    /**
     * Returns a paginated view of all L2 cache entries, ordered by
     * {@code next_update} descending (entries closest to expiry first).
     */
    public Page<CacheEntryDto> listEntries(Pageable pageable) {
        return cacheRepository.findAll(pageable).map(this::toDto);
    }

    /**
     * Looks up a cache entry by its raw cache key (40-char SHA-1 hex).
     */
    public Optional<CacheEntryDto> findByCacheKey(String cacheKey) {
        return cacheRepository.findById(cacheKey).map(this::toDto);
    }

    // -------------------------------------------------------------------------
    // Invalidation
    // -------------------------------------------------------------------------

    /**
     * Manually invalidates a single cache entry.
     *
     * <ol>
     *   <li>Deletes the row from {@code ocsp_response_cache} (L2).</li>
     *   <li>Publishes an invalidation message to
     *       {@code ocsp.internal / ocsp.cache.invalidate} so all responder pods
     *       evict the entry from their Caffeine L1 caches.</li>
     * </ol>
     *
     * <p>If the entry does not exist the method is a no-op (idempotent).
     *
     * @param cacheKey   40-char SHA-1 hex of the CertID
     * @param operatorId JWT {@code sub} claim of the operator (for audit trail)
     */
    @Transactional
    public void invalidate(String cacheKey, String operatorId) {
        log.info("Manual cache invalidation requested: cacheKey={} operator={}", cacheKey, operatorId);

        boolean existed = cacheRepository.existsById(cacheKey);
        if (existed) {
            cacheRepository.deleteById(cacheKey);
            log.debug("Deleted L2 cache entry: cacheKey={}", cacheKey);
        } else {
            log.info("Cache entry not found in L2 (may have already expired): cacheKey={}", cacheKey);
        }

        // Publish invalidation signal regardless — ensures L1 is always cleared
        // even if the L2 row was already gone (e.g. expired).
        rabbitTemplate.convertAndSend(
            cacheInvalidationExchange,
            cacheInvalidationRoutingKey,
            Map.of(
                "cacheKey",    cacheKey,
                "triggeredBy", "manual",
                "operatorId",  operatorId
            )
        );

        log.info("Cache invalidation signal published: cacheKey={} operator={} l2Deleted={}",
                cacheKey, operatorId, existed);
    }

    // -------------------------------------------------------------------------
    // Mapping
    // -------------------------------------------------------------------------

    private CacheEntryDto toDto(OcspResponseCache entity) {
        return CacheEntryDto.builder()
                .cacheKey(entity.getCacheKey())
                .thisUpdate(entity.getThisUpdate())
                .nextUpdate(entity.getNextUpdate())
                .createdAt(entity.getCreatedAt())
                .responseSizeBytes(entity.getDerResponse() != null
                        ? entity.getDerResponse().length : 0)
                .build();
    }
}
