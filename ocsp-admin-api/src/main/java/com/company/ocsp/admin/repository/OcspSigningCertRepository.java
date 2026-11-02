package com.company.ocsp.admin.repository;

import com.company.ocsp.admin.model.OcspSigningCert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OcspSigningCertRepository extends JpaRepository<OcspSigningCert, Long> {

    /** Returns the currently-active delegated OCSP signing certificate. */
    Optional<OcspSigningCert> findFirstByIsActiveTrueOrderByNotBeforeDesc();
}
