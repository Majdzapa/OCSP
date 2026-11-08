package com.company.incert.kms.adapter.out.jpa;

import com.company.incert.kms.application.port.out.CertificateRepository;
import com.company.incert.kms.domain.Certificate;
import com.company.incert.kms.domain.CertificateStatus;
import lombok.RequiredArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JpaCertificateRepositoryAdapter implements CertificateRepository {

    private final SpringDataCertificateRepository repo;

    @Override
    public Certificate save(Certificate cert) {
        CertificateJpaEntity entity = toEntity(cert);
        entity.setUpdatedAt(Instant.now());
        // find existing to preserve auto-generated id for update
        repo.findBySerialNumberHex(cert.serialNumberHex()).ifPresent(e -> entity.setId(e.getId()));
        return toDomain(repo.save(entity));
    }

    @Override
    public Optional<Certificate> findBySerial(String serialHex) {
        return repo.findBySerialNumberHex(serialHex).map(this::toDomain);
    }

    @Override
    public List<Certificate> findAll() {
        return repo.findAll().stream().map(this::toDomain).collect(Collectors.toList());
    }

    @Override
    public List<Certificate> findByStatus(CertificateStatus status) {
        return repo.findByStatus(status).stream().map(this::toDomain).collect(Collectors.toList());
    }

    @Override
    public long count() {
        return repo.count();
    }

    private CertificateJpaEntity toEntity(Certificate c) {
        return CertificateJpaEntity.builder()
                .serialNumberHex(c.serialNumberHex())
                .issuerDn(c.issuerDn())
                .issuerKeyHashHex(c.issuerKeyHashHex())
                .issuerNameHashHex(c.issuerNameHashHex())
                .subjectDn(c.subjectDn())
                .notBefore(c.notBefore())
                .notAfter(c.notAfter())
                .status(c.status())
                .revocationTime(c.revocationTime())
                .revocationReason(c.revocationReason())
                .pemEncoded(c.pemEncoded())
                .sequence(c.sequence())
                .updatedAt(Instant.now())
                .build();
    }

    private Certificate toDomain(CertificateJpaEntity e) {
        return new Certificate(
                e.getSerialNumberHex(), e.getIssuerDn(), e.getIssuerKeyHashHex(),
                e.getIssuerNameHashHex(), e.getSubjectDn(), e.getNotBefore(), e.getNotAfter(),
                e.getStatus(), e.getRevocationTime(), e.getRevocationReason(),
                e.getPemEncoded(), e.getSequence()
        );
    }
}
