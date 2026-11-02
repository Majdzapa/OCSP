package com.company.ocsp.sync.repository;

import com.company.ocsp.sync.model.RevocationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RevocationStatusRepository extends JpaRepository<RevocationStatus, Long> {

    Optional<RevocationStatus> findBySourceEventId(String sourceEventId);

    /** Counts certificates in a specific status — used by the reconciliation job. */
    long countByStatus(RevocationStatus.CertStatus status);

    @Query("""
        SELECT rs FROM RevocationStatus rs
        WHERE rs.issuerNameHash = :inh
          AND rs.issuerKeyHash  = :ikh
          AND rs.serialNumber   = :sn
        """)
    Optional<RevocationStatus> findByCertId(
        @Param("inh") byte[] issuerNameHash,
        @Param("ikh") byte[] issuerKeyHash,
        @Param("sn")  byte[] serialNumber
    );

    /**
     * Upsert-style update: if a record already exists for the CertID triple,
     * update its status fields.  Otherwise insert via {@link #save(Object)}.
     */
    @Modifying
    @Query("""
        UPDATE RevocationStatus rs
        SET rs.status            = :status,
            rs.revocationTime    = :revocationTime,
            rs.revocationReason  = :revocationReason,
            rs.thisUpdate        = :thisUpdate,
            rs.sourceEventId     = :sourceEventId,
            rs.updatedAt         = :updatedAt
        WHERE rs.issuerNameHash  = :inh
          AND rs.issuerKeyHash   = :ikh
          AND rs.serialNumber    = :sn
        """)
    int updateByCertId(
        @Param("inh")             byte[] issuerNameHash,
        @Param("ikh")             byte[] issuerKeyHash,
        @Param("sn")              byte[] serialNumber,
        @Param("status")          RevocationStatus.CertStatus status,
        @Param("revocationTime")  java.time.Instant revocationTime,
        @Param("revocationReason") String revocationReason,
        @Param("thisUpdate")      java.time.Instant thisUpdate,
        @Param("sourceEventId")   String sourceEventId,
        @Param("updatedAt")       java.time.Instant updatedAt
    );
}
