package com.company.incert.ocsp.status.application.port.out;

import com.company.incert.ocsp.shared.CertificateStatusRecord;

/** Driven port: idempotent upsert of certificate status. */
public interface StatusWriter {
    /**
     * Upsert the status. If a record exists with equal or higher sequence, skip (out-of-order protection).
     * @return true if the record was updated, false if skipped (older/duplicate)
     */
    boolean upsert(CertificateStatusRecord record);
}
