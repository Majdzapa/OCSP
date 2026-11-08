package com.company.incert.ocsp.status.application.port.in;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.shared.CertificateStatusRecord;

import java.util.Optional;

public interface LookupStatusUseCase {
    Optional<CertificateStatusRecord> lookup(CertId certId);
}
