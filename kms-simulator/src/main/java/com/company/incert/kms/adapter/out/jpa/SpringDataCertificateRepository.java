package com.company.incert.kms.adapter.out.jpa;

import com.company.incert.kms.domain.CertificateStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SpringDataCertificateRepository extends JpaRepository<CertificateJpaEntity, Long> {
    Optional<CertificateJpaEntity> findBySerialNumberHex(String serialHex);
    List<CertificateJpaEntity> findByStatus(CertificateStatus status);
}
