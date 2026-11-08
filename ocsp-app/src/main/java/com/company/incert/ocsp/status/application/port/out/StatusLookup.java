package com.company.incert.ocsp.status.application.port.out;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.shared.CertificateStatusRecord;

import java.util.Optional;

/** Driven port: look up a certificate's current OCSP status. */
public interface StatusLookup {
    Optional<CertificateStatusRecord> findStatus(CertId certId);
}
