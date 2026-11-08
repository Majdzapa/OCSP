package com.company.incert.kms.application.port.in;

import com.company.incert.kms.domain.Certificate;
import com.company.incert.kms.domain.RevocationReason;

public interface RevokeCertificateUseCase {
    Certificate revoke(String serialHex, RevocationReason reason);
}
