package com.company.ocsp.admin.repository;

import com.company.ocsp.admin.model.CertEventAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

@Repository
public interface CertEventAuditRepository extends JpaRepository<CertEventAudit, String> {

    /** Ordered by received_at desc — used by the revocation feed. */
    Page<CertEventAudit> findAllByOrderByReceivedAtDesc(Pageable pageable);

    /** Count of failed events for dashboard error-rate indicator. */
    long countByStatus(CertEventAudit.ProcessingStatus status);
}
