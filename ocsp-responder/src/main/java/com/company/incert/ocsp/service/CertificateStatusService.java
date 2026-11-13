package com.company.incert.ocsp.service;

import com.company.incert.ocsp.entity.CertificateStatus;
import com.company.incert.ocsp.entity.RevocationReason;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.messaging.CertificateStatusEvent;
import com.company.incert.ocsp.repository.RevocationStatusRepository;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

/**
 * Reads and writes the replicated certificate status table.
 * No caching: every OCSP request reads the database directly.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateStatusService {

    private final RevocationStatusRepository repository;
    private final MeterRegistry meterRegistry;

    @Transactional(readOnly = true)
    public Optional<RevocationStatus> findByCertId(byte[] issuerNameHash, byte[] issuerKeyHash, byte[] serialNumber) {
        return repository.findByCertId(issuerNameHash, issuerKeyHash, serialNumber);
    }

    @Transactional(readOnly = true)
    public Optional<RevocationStatus> findBySerialHex(String serialHex) {
        byte[] serial = parseHex(serialHex);
        return repository.findBySerialNumber(serial).stream().findFirst();
    }

    @Transactional(readOnly = true)
    public Page<RevocationStatus> findRevoked(int page, int size) {
        return repository.findByStatus(CertificateStatus.REVOKED,
            PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 200), Sort.by("updatedAt").descending()));
    }

    @Transactional(readOnly = true)
    public long countAll() {
        return repository.count();
    }

    @Transactional(readOnly = true)
    public long countByStatus(CertificateStatus status) {
        return repository.countByStatus(status);
    }

    /**
     * Applies a status change coming from RabbitMQ or from reconciliation.
     * <p>
     * Ordering/idempotency rule based on the KMS per-certificate {@code sequence}:
     * <ul>
     *   <li>incoming sequence &lt; stored sequence → stale, ignored</li>
     *   <li>same sequence and same status/reason → duplicate delivery, ignored</li>
     *   <li>otherwise → applied</li>
     * </ul>
     *
     * @return true if the row was inserted or updated
     */
    @Transactional
    public boolean applyStatusChange(CertificateStatusEvent event) {
        byte[] nameHash = parseHex(event.issuerNameHashHex());
        byte[] keyHash = parseHex(event.issuerKeyHashHex());
        byte[] serial = parseHex(event.serialNumberHex());
        RevocationReason reason = RevocationReason.parse(event.revocationReason());
        String reasonName = reason != null ? reason.name() : null;
        Instant now = Instant.now();

        Optional<RevocationStatus> existing = repository.findByCertId(nameHash, keyHash, serial);
        if (existing.isPresent()) {
            RevocationStatus row = existing.get();
            boolean stale = event.sequence() < row.getSequence();
            boolean duplicate = event.sequence() == row.getSequence()
                && row.getStatus() == event.status()
                && Objects.equals(row.getRevocationReason(), reasonName);
            if (stale || duplicate) {
                log.debug("Skipping {} event {} for serial={} (stored seq={}, incoming seq={})",
                    stale ? "stale" : "duplicate", event.eventId(), event.serialNumberHex(),
                    row.getSequence(), event.sequence());
                meterRegistry.counter("ocsp.sync.skipped").increment();
                return false;
            }
            row.setStatus(event.status());
            row.setRevocationTime(event.status() == CertificateStatus.REVOKED ? event.revocationTime() : null);
            row.setRevocationReason(event.status() == CertificateStatus.REVOKED ? reasonName : null);
            row.setThisUpdate(now);
            row.setSourceEventId(event.eventId());
            row.setUpdatedAt(now);
            row.setSequence(event.sequence());
            repository.save(row);
        } else {
            repository.save(RevocationStatus.builder()
                .issuerNameHash(nameHash)
                .issuerKeyHash(keyHash)
                .serialNumber(serial)
                .status(event.status())
                .revocationTime(event.status() == CertificateStatus.REVOKED ? event.revocationTime() : null)
                .revocationReason(event.status() == CertificateStatus.REVOKED ? reasonName : null)
                .thisUpdate(now)
                .sourceEventId(event.eventId())
                .updatedAt(now)
                .sequence(event.sequence())
                .build());
        }
        log.info("Applied status change: eventId={} serial={} status={} seq={}",
            event.eventId(), event.serialNumberHex(), event.status(), event.sequence());
        meterRegistry.counter("ocsp.sync.applied").increment();
        return true;
    }

    static byte[] parseHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex value is required");
        }
        String clean = hex.toLowerCase().replaceAll("[^0-9a-f]", "");
        if (clean.length() % 2 != 0) {
            clean = "0" + clean;
        }
        return HexFormat.of().parseHex(clean);
    }
}

