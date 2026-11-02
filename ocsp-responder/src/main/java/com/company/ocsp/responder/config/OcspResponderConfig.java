package com.company.ocsp.responder.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * Application-wide beans for the OCSP Responder.
 */
@Configuration
public class OcspResponderConfig {

    // ---- Caffeine L1 cache configuration ----

    @Value("${ocsp.cache.l1.max-size:10000}")
    private int l1MaxSize;

    @Value("${ocsp.cache.l1.expire-after-write-minutes:60}")
    private int l1ExpireMinutes;

    /**
     * L1 Caffeine cache: bounded, time-limited, per-JVM.
     * Key: CertID SHA-1 hex string (40 chars).
     * Value: DER-encoded OCSPResponse bytes.
     */
    @Bean
    public Cache<String, byte[]> caffeineL1Cache() {
        return Caffeine.newBuilder()
            .maximumSize(l1MaxSize)
            .expireAfterWrite(Duration.ofMinutes(l1ExpireMinutes))
            .recordStats()
            .build();
    }

    // KMS HTTP client is configured in KmsClientConfig — see that class.
}
