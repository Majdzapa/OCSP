package com.company.incert.kms.application.port.out;

import com.company.incert.kms.domain.CertificateStatusChangedEvent;

public interface OutboxWriter {
    /** Persist an event to the outbox table (same transaction as the status change). */
    void write(CertificateStatusChangedEvent event);
}
