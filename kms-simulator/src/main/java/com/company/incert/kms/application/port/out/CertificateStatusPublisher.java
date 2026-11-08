package com.company.incert.kms.application.port.out;

import com.company.incert.kms.domain.CertificateStatusChangedEvent;

public interface CertificateStatusPublisher {
    void publish(CertificateStatusChangedEvent event);
}
