package com.company.incert.ocsp.status.config;

import com.company.incert.ocsp.status.adapter.out.cache.CaffeineStatusCacheAdapter;
import com.company.incert.ocsp.status.adapter.out.jpa.JpaStatusRepositoryAdapter;
import com.company.incert.ocsp.status.adapter.out.jpa.SpringDataRevocationStatusRepository;
import com.company.incert.ocsp.status.application.port.in.LookupStatusUseCase;
import com.company.incert.ocsp.status.application.port.out.CacheEvictor;
import com.company.incert.ocsp.status.application.port.out.StatusWriter;
import com.company.incert.ocsp.status.application.service.CachingStatusLookupService;
import com.company.incert.ocsp.shared.CertificateStatusRecord;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class StatusModuleConfig {

    @Value("${ocsp.cache.l1.max-size:10000}")
    private long maxSize;

    @Value("${ocsp.cache.l1.expire-after-write-minutes:60}")
    private long expireMinutes;

    @Bean
    public Cache<String, CertificateStatusRecord> statusCaffeineCache() {
        return Caffeine.newBuilder()
            .maximumSize(maxSize)
            .expireAfterWrite(expireMinutes, TimeUnit.MINUTES)
            .recordStats()
            .build();
    }

    @Bean
    public CaffeineStatusCacheAdapter caffeineStatusCacheAdapter(Cache<String, CertificateStatusRecord> cache) {
        return new CaffeineStatusCacheAdapter(cache);
    }

    @Bean
    public JpaStatusRepositoryAdapter jpaStatusRepositoryAdapter(SpringDataRevocationStatusRepository repo) {
        return new JpaStatusRepositoryAdapter(repo);
    }

    @Bean
    public LookupStatusUseCase lookupStatusUseCase(
            CaffeineStatusCacheAdapter cacheAdapter,
            JpaStatusRepositoryAdapter jpaAdapter,
            MeterRegistry meterRegistry) {
        return new CachingStatusLookupService(cacheAdapter, jpaAdapter, meterRegistry);
    }

    @Bean
    public StatusWriter statusWriter(JpaStatusRepositoryAdapter jpaAdapter) {
        return jpaAdapter;
    }

    @Bean
    public com.company.incert.ocsp.status.application.port.out.StatusStatsPort statusStatsPort(JpaStatusRepositoryAdapter jpaAdapter) {
        return jpaAdapter;
    }

    @Bean
    public CacheEvictor cacheEvictor(CaffeineStatusCacheAdapter cacheAdapter) {
        return cacheAdapter;
    }
}
