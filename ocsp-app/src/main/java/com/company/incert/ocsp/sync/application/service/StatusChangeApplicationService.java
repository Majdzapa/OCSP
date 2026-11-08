package com.company.incert.ocsp.sync.application.service;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.status.application.port.out.CacheEvictor;
import com.company.incert.ocsp.status.application.port.out.StatusWriter;
import com.company.incert.ocsp.shared.CertificateStatusRecord;
import com.company.incert.ocsp.sync.application.port.in.ApplyStatusChangeUseCase;
import com.company.incert.ocsp.sync.domain.StatusChangeCommand;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Core sync use-case: persists status changes and evicts cache.
 * Depends only on domain + ports. No Kafka, no JPA directly.
 */
@Slf4j
@RequiredArgsConstructor
public class StatusChangeApplicationService implements ApplyStatusChangeUseCase {

    private final StatusWriter statusWriter;
    private final CacheEvictor cacheEvictor;
    private final MeterRegistry meterRegistry;

    @Override
    @Transactional
    public void apply(StatusChangeCommand cmd) {
        log.info("Applying status change: eventId={} status={} serial={}",
            cmd.eventId(), cmd.status(), toHex(cmd.serialNumber()));

        CertificateStatusRecord record = new CertificateStatusRecord(
            cmd.issuerNameHash(), cmd.issuerKeyHash(), cmd.serialNumber(),
            cmd.status(), cmd.revocationTime(), cmd.revocationReason(),
            Instant.now(), cmd.eventId(), cmd.sequence()
        );

        boolean updated = statusWriter.upsert(record);
        if (updated) {
            // Direct in-process cache invalidation — single deployment unit!
            CertId certId = new CertId(cmd.issuerNameHash(), cmd.issuerKeyHash(), cmd.serialNumber());
            cacheEvictor.evict(certId);
            meterRegistry.counter("ocsp.sync.applied").increment();
            log.debug("Status updated and cache evicted for serial={}", toHex(cmd.serialNumber()));
        } else {
            meterRegistry.counter("ocsp.sync.skipped").increment();
            log.debug("Status change skipped (duplicate/stale) for serial={}", toHex(cmd.serialNumber()));
        }
    }

    private static String toHex(byte[] b) {
        return java.util.HexFormat.of().formatHex(b);
    }
}
