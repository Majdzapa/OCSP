package com.company.ocsp.sync.repository;

import com.company.ocsp.sync.model.CertEventAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CertEventAuditRepository extends JpaRepository<CertEventAudit, String> {
}
