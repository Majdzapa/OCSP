package com.company.ocsp.admin.repository;

import com.company.ocsp.admin.model.RevocationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RevocationStatusRepository extends JpaRepository<RevocationStatus, Long> {

    /** Count revoked certs — used by dashboard stats. */
    long countByStatus(RevocationStatus.CertStatus status);

    /**
     * Looks up a certificate's revocation record by its serial number (raw bytes).
     * The serial is passed as a byte array decoded from the hex string provided by the caller.
     */
    @Query("SELECT r FROM RevocationStatus r WHERE r.serialNumber = :serial ORDER BY r.id DESC")
    Optional<RevocationStatus> findTopBySerialNumber(@Param("serial") byte[] serial);
}

