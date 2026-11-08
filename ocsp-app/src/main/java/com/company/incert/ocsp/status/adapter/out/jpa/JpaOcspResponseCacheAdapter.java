package com.company.incert.ocsp.status.adapter.out.jpa;

import com.company.incert.ocsp.status.application.port.out.OcspResponseCachePort;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class JpaOcspResponseCacheAdapter implements OcspResponseCachePort {

    private final SpringDataOcspResponseCacheRepository repo;

    @Override
    public Optional<byte[]> getResponse(String cacheKey) {
        return repo.findById(cacheKey)
            .filter(e -> e.getNextUpdate().isAfter(Instant.now()))
            .map(OcspResponseCacheJpaEntity::getDerResponse);
    }

    @Override
    public void saveResponse(String cacheKey, byte[] derResponse, Instant thisUpdate, Instant nextUpdate) {
        OcspResponseCacheJpaEntity entity = OcspResponseCacheJpaEntity.builder()
            .cacheKey(cacheKey)
            .derResponse(derResponse)
            .thisUpdate(thisUpdate)
            .nextUpdate(nextUpdate)
            .createdAt(Instant.now())
            .build();
        repo.save(entity);
        log.debug("Saved L2 OCSP response cache for key={}", cacheKey);
    }

    @Override
    public void evict(String cacheKey) {
        if (repo.existsById(cacheKey)) {
            repo.deleteById(cacheKey);
            log.debug("Evicted L2 cache entry key={}", cacheKey);
        }
    }

    @Override
    public void evictAll() {
        repo.deleteAll();
        log.info("Evicted all entries from L2 OCSP response cache");
    }

    @Override
    public List<Map<String, Object>> getCacheEntries(int page, int size) {
        var pageable = PageRequest.of(page, Math.min(size, 100), Sort.by("nextUpdate").descending());
        return repo.findAll(pageable).stream().map(e -> Map.<String, Object>of(
            "cacheKey", e.getCacheKey(),
            "thisUpdate", e.getThisUpdate().toString(),
            "nextUpdate", e.getNextUpdate().toString(),
            "createdAt", e.getCreatedAt().toString(),
            "responseSizeBytes", e.getDerResponse() != null ? e.getDerResponse().length : 0
        )).toList();
    }

    @Override
    public long count() {
        return repo.count();
    }
}
