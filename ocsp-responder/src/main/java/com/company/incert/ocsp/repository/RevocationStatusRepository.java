package com.company.incert.ocsp.repository;

import com.company.incert.ocsp.entity.CertificateStatus;
import com.company.incert.ocsp.entity.RevocationStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface RevocationStatusRepository extends JpaRepository<RevocationStatus, Long> {

    @Query("SELECT r FROM RevocationStatus r WHERE "
         + "r.issuerNameHash = :nameHash AND r.issuerKeyHash = :keyHash AND r.serialNumber = :serial")
    Optional<RevocationStatus> findByCertId(
        @Param("nameHash") byte[] issuerNameHash,
        @Param("keyHash") byte[] issuerKeyHash,
        @Param("serial") byte[] serialNumber);

    List<RevocationStatus> findBySerialNumber(byte[] serialNumber);

    Page<RevocationStatus> findByStatus(CertificateStatus status, Pageable pageable);

    long countByStatus(CertificateStatus status);
}

