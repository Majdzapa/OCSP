package com.company.incert.ocsp.status.adapter.out.jpa;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.shared.domain.RevocationReason;
import com.company.incert.ocsp.status.application.port.out.StatusLookup;
import com.company.incert.ocsp.status.application.port.out.StatusWriter;
import com.company.incert.ocsp.shared.CertificateStatusRecord;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class JpaStatusRepositoryAdapter implements StatusLookup, StatusWriter, com.company.incert.ocsp.status.application.port.out.StatusStatsPort {

    private final SpringDataRevocationStatusRepository repo;

    @Override
    public long countTotal() {
        return repo.count();
    }

    @Override
    public long countRevoked() {
        return repo.countByStatus(com.company.incert.ocsp.shared.domain.CertificateStatus.REVOKED);
    }

    @Override
    public long countGood() {
        return repo.countByStatus(com.company.incert.ocsp.shared.domain.CertificateStatus.GOOD);
    }

    @Override
    public java.util.List<java.util.Map<String, String>> getRevokedPage(int page, int size) {
        var pageable = org.springframework.data.domain.PageRequest.of(page, Math.min(size, 200),
            org.springframework.data.domain.Sort.by("updatedAt").descending());
        var list = repo.findAll(pageable).stream()
            .filter(e -> e.getStatus() == com.company.incert.ocsp.shared.domain.CertificateStatus.REVOKED)
            .toList();
        java.util.HexFormat hex = java.util.HexFormat.of();
        return list.stream().map(e -> java.util.Map.of(
            "serialNumber", hex.formatHex(e.getSerialNumber()),
            "issuerKeyHash", hex.formatHex(e.getIssuerKeyHash()),
            "revocationTime", e.getRevocationTime() != null ? e.getRevocationTime().toString() : "",
            "revocationReason", e.getRevocationReason() != null ? e.getRevocationReason() : "UNSPECIFIED",
            "thisUpdate", e.getThisUpdate().toString()
        )).toList();
    }

    @Override
    public Optional<CertificateStatusRecord> findStatus(CertId certId) {
        return repo.findByCertId(certId.issuerNameHash(), certId.issuerKeyHash(), certId.serialNumber())
            .map(this::toDomain);
    }

    @Override
    public boolean upsert(CertificateStatusRecord record) {
        try {
            Optional<RevocationStatusJpaEntity> existing =
                repo.findByCertId(record.issuerNameHash(), record.issuerKeyHash(), record.serialNumber());

            if (existing.isPresent()) {
                RevocationStatusJpaEntity entity = existing.get();
                // Out-of-order protection: skip if stored sequence >= incoming
                if (entity.getSequence() >= record.sequence()) {
                    log.debug("Skipping stale event for serial={}: stored seq={} >= incoming seq={}",
                        toHex(record.serialNumber()), entity.getSequence(), record.sequence());
                    return false;
                }
                entity.setStatus(record.status());
                entity.setRevocationTime(record.revocationTime());
                entity.setRevocationReason(record.revocationReason() != null ? record.revocationReason().name() : null);
                entity.setThisUpdate(record.thisUpdate());
                entity.setSourceEventId(record.sourceEventId());
                entity.setUpdatedAt(Instant.now());
                entity.setSequence(record.sequence());
                repo.save(entity);
            } else {
                RevocationStatusJpaEntity entity = toEntity(record);
                repo.save(entity);
            }
            return true;
        } catch (DataIntegrityViolationException e) {
            // Duplicate source_event_id — idempotent, ignore
            log.debug("Duplicate event id={} — skipping (idempotent)", record.sourceEventId());
            return false;
        }
    }

    private CertificateStatusRecord toDomain(RevocationStatusJpaEntity e) {
        RevocationReason reason = null;
        if (e.getRevocationReason() != null) {
            try {
                reason = RevocationReason.valueOf(e.getRevocationReason());
            } catch (Exception ex) {
                /* ignore */
            }
        }
        return new CertificateStatusRecord(
            e.getIssuerNameHash(), e.getIssuerKeyHash(), e.getSerialNumber(),
            e.getStatus(), e.getRevocationTime(), reason,
            e.getThisUpdate(), e.getSourceEventId(), e.getSequence()
        );
    }

    private RevocationStatusJpaEntity toEntity(CertificateStatusRecord r) {
        return RevocationStatusJpaEntity.builder()
            .issuerNameHash(r.issuerNameHash())
            .issuerKeyHash(r.issuerKeyHash())
            .serialNumber(r.serialNumber())
            .status(r.status())
            .revocationTime(r.revocationTime())
            .revocationReason(r.revocationReason() != null ? r.revocationReason().name() : null)
            .thisUpdate(r.thisUpdate())
            .sourceEventId(r.sourceEventId())
            .updatedAt(Instant.now())
            .sequence(r.sequence())
            .build();
    }

    private static String toHex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }
}
