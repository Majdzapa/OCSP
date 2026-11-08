package com.company.incert.kms.application.port.out;

import com.company.incert.kms.domain.Certificate;
import com.company.incert.kms.domain.CertificateStatus;

import java.util.List;
import java.util.Optional;

public interface CertificateRepository {
    Certificate save(Certificate certificate);
    Optional<Certificate> findBySerial(String serialHex);
    List<Certificate> findAll();
    List<Certificate> findByStatus(CertificateStatus status);
    long count();
}
