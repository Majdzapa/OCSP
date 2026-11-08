package com.company.incert.ocsp.status.application.service;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.status.application.port.in.LookupStatusUseCase;
import com.company.incert.ocsp.status.application.port.out.StatusLookup;
import com.company.incert.ocsp.shared.CertificateStatusRecord;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

/**
 * Composed status lookup: checks cache first, then DB.
 * Implements LookupStatusUseCase — called by the responder module.
 */
@Slf4j
@RequiredArgsConstructor
public class CachingStatusLookupService implements LookupStatusUseCase {

    private final StatusLookup cacheLayer;    // CaffeineStatusCacheAdapter (checks cache)
    private final StatusLookup dbLayer;       // JpaStatusRepositoryAdapter (fallback)
    private final MeterRegistry meterRegistry;

    @Override
    public Optional<CertificateStatusRecord> lookup(CertId certId) {
        Optional<CertificateStatusRecord> cached = cacheLayer.findStatus(certId);
        if (cached.isPresent()) {
            meterRegistry.counter("ocsp.status.cache.hit").increment();
            return cached;
        }
        meterRegistry.counter("ocsp.status.cache.miss").increment();
        return dbLayer.findStatus(certId);
    }
}
