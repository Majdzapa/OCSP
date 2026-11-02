package com.company.ocsp.responder.repository;

import com.company.ocsp.responder.model.OcspResponseCache;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

/**
 * Repository for the L2 shared OCSP response cache.
 * Both the responder (read) and the cache maintenance job (write/evict) use this.
 */
@Repository
public interface OcspResponseCacheRepository extends JpaRepository<OcspResponseCache, String> {

    /**
     * Finds a cached response that has not yet reached its {@code nextUpdate}.
     */
    @Query("SELECT c FROM OcspResponseCache c WHERE c.cacheKey = :key AND c.nextUpdate > :now")
    Optional<OcspResponseCache> findValidByCacheKey(String key, Instant now);

    /**
     * Purges all expired cache entries.  Called by a scheduled maintenance task.
     */
    @Modifying
    @Query("DELETE FROM OcspResponseCache c WHERE c.nextUpdate <= :now")
    int deleteExpired(Instant now);
}
