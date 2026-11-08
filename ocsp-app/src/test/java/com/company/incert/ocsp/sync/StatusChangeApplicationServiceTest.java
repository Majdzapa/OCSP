package com.company.incert.ocsp.sync;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.shared.domain.CertificateStatus;
import com.company.incert.ocsp.shared.domain.RevocationReason;
import com.company.incert.ocsp.status.application.port.out.CacheEvictor;
import com.company.incert.ocsp.status.application.port.out.StatusWriter;
import com.company.incert.ocsp.shared.CertificateStatusRecord;
import com.company.incert.ocsp.sync.application.service.StatusChangeApplicationService;
import com.company.incert.ocsp.sync.domain.StatusChangeCommand;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

class StatusChangeApplicationServiceTest {

    private SimpleMeterRegistry meterRegistry;
    private AtomicBoolean evicted;

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        evicted = new AtomicBoolean(false);
    }

    @Test
    void shouldApplyAndEvictCacheWhenUpsertSucceeds() {
        StatusWriter statusWriter = record -> true;
        CacheEvictor cacheEvictor = new CacheEvictor() {
            @Override
            public void evict(CertId certId) {
                evicted.set(true);
            }
            @Override
            public void evictAll() {}
        };

        StatusChangeApplicationService service =
            new StatusChangeApplicationService(statusWriter, cacheEvictor, meterRegistry);

        StatusChangeCommand cmd = new StatusChangeCommand(
            "event-101", new byte[]{1}, new byte[]{2}, new byte[]{3},
            CertificateStatus.REVOKED, Instant.now(), RevocationReason.KEY_COMPROMISE,
            Instant.now(), 5
        );

        service.apply(cmd);

        assertThat(evicted.get()).isTrue();
        assertThat(meterRegistry.counter("ocsp.sync.applied").count()).isEqualTo(1.0);
    }

    @Test
    void shouldSkipCacheEvictionWhenUpsertReportsStaleSequence() {
        StatusWriter statusWriter = record -> false; // skipped due to stale sequence
        CacheEvictor cacheEvictor = new CacheEvictor() {
            @Override
            public void evict(CertId certId) {
                evicted.set(true);
            }
            @Override
            public void evictAll() {}
        };

        StatusChangeApplicationService service =
            new StatusChangeApplicationService(statusWriter, cacheEvictor, meterRegistry);

        StatusChangeCommand cmd = new StatusChangeCommand(
            "event-old", new byte[]{1}, new byte[]{2}, new byte[]{3},
            CertificateStatus.GOOD, null, null,
            Instant.now(), 2
        );

        service.apply(cmd);

        assertThat(evicted.get()).isFalse();
        assertThat(meterRegistry.counter("ocsp.sync.skipped").count()).isEqualTo(1.0);
    }
}
