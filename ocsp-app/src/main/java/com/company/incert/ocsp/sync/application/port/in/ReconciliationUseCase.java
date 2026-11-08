package com.company.incert.ocsp.sync.application.port.in;

import java.time.Instant;
import java.util.Map;

/**
 * Driving port for reconciling OCSP database state against the KMS certificate snapshot.
 */
public interface ReconciliationUseCase {
    Map<String, Object> runReconciliation();
    boolean isLastReconciliationOk();
    Instant getLastReconciliationTime();
}

