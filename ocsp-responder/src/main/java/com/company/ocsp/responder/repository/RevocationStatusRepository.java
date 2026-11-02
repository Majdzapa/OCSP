package com.company.ocsp.responder.repository;

import com.company.ocsp.responder.model.RevocationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Read-only repository for the {@code revocation_status} table.
 * The responder service is granted DB-level SELECT only on this table;
 * writes belong exclusively to {@code ocsp-sync-service}.
 */
@Repository
public interface RevocationStatusRepository extends JpaRepository<RevocationStatus, Long> {

    /**
     * Looks up a certificate's status by its RFC 6960 {@code CertID} triple.
     *
     * @param issuerNameHash SHA-1 hash of the issuer DN (20 bytes)
     * @param issuerKeyHash  SHA-1 hash of the issuer public key (20 bytes)
     * @param serialNumber   certificate serial number bytes
     * @return the most recent status record, if known
     */
    @Query("""
        SELECT rs FROM RevocationStatus rs
        WHERE rs.issuerNameHash = :issuerNameHash
          AND rs.issuerKeyHash  = :issuerKeyHash
          AND rs.serialNumber   = :serialNumber
        """)
    Optional<RevocationStatus> findByCertId(
        @Param("issuerNameHash") byte[] issuerNameHash,
        @Param("issuerKeyHash")  byte[] issuerKeyHash,
        @Param("serialNumber")   byte[] serialNumber
    );
}
