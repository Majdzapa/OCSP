package com.company.incert.ocsp.contract;

import com.company.incert.ocsp.shared.CertificateStatusRecord;
import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.status.application.port.out.StatusLookup;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Abstract contract test for StatusLookup port implementations.
 */
public abstract class StatusLookupContract {

    protected abstract StatusLookup createStatusLookup();
    protected abstract void populate(CertId certId, CertificateStatusRecord record);

    @Test
    void shouldReturnEmptyForUnknownCertId() {
        StatusLookup lookup = createStatusLookup();
        CertId certId = new CertId(new byte[]{1, 2, 3}, new byte[]{4, 5, 6}, new byte[]{7, 8, 9});
        Optional<CertificateStatusRecord> result = lookup.findStatus(certId);
        assertThat(result).isEmpty();
    }

    @Test
    void shouldFindStatusWhenPopulated() {
        StatusLookup lookup = createStatusLookup();
        CertId certId = new CertId(new byte[]{1, 2, 3}, new byte[]{4, 5, 6}, new byte[]{7, 8, 9});
        CertificateStatusRecord record = new CertificateStatusRecord(
            certId.issuerNameHash(), certId.issuerKeyHash(), certId.serialNumber(),
            com.company.incert.ocsp.shared.domain.CertificateStatus.GOOD, null, null,
            java.time.Instant.now(), "event-1", 1
        );
        populate(certId, record);

        Optional<CertificateStatusRecord> result = lookup.findStatus(certId);
        assertThat(result).isPresent();
        assertThat(result.get().sourceEventId()).isEqualTo("event-1");
    }
}

