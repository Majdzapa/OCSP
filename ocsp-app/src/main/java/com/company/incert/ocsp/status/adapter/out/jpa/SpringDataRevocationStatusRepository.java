package com.company.incert.ocsp.status.adapter.out.jpa;

import com.company.incert.ocsp.shared.domain.CertificateStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface SpringDataRevocationStatusRepository extends JpaRepository<RevocationStatusJpaEntity, Long> {

    @Query("SELECT r FROM RevocationStatusJpaEntity r WHERE " +
           "r.issuerNameHash = :nameHash AND r.issuerKeyHash = :keyHash AND r.serialNumber = :serial")
    Optional<RevocationStatusJpaEntity> findByCertId(
        @Param("nameHash") byte[] issuerNameHash,
        @Param("keyHash") byte[] issuerKeyHash,
        @Param("serial") byte[] serialNumber);

    long countByStatus(CertificateStatus status);
}

