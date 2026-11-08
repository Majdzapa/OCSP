package com.company.incert.kms.application.port.in;

import com.company.incert.kms.domain.Certificate;

public interface UnrevokeCertificateUseCase {
    Certificate unrevoke(String serialHex);
}
