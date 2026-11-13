package com.company.incert.kms.application.port.in;

import com.company.incert.kms.domain.Certificate;
import com.company.incert.kms.domain.CertificateStatus;
import com.company.incert.kms.domain.RevocationReason;

import java.time.Instant;

public interface UpdateCertificateStatusUseCase {
    Certificate updateStatus(String serialHex, CertificateStatus status, RevocationReason reason, Instant revocationTime);
}

