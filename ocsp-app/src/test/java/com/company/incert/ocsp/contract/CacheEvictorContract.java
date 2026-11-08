package com.company.incert.ocsp.contract;

import com.company.incert.ocsp.shared.CertificateStatusRecord;
import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.status.application.port.out.CacheEvictor;
import com.company.incert.ocsp.status.application.port.out.StatusLookup;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public abstract class CacheEvictorContract {

    protected abstract CacheEvictor createEvictor();
    protected abstract StatusLookup asLookup();
    protected abstract void populate(CertId certId, CertificateStatusRecord record);

    @Test
    void shouldEvictSpecificCertId() {
        CacheEvictor evictor = createEvictor();
        StatusLookup lookup = asLookup();

        CertId certId = new CertId(new byte[]{1}, new byte[]{2}, new byte[]{3});
        CertificateStatusRecord record = new CertificateStatusRecord(
            certId.issuerNameHash(), certId.issuerKeyHash(), certId.serialNumber(),
            com.company.incert.ocsp.shared.domain.CertificateStatus.GOOD, null, null,
            java.time.Instant.now(), "event-1", 1
        );
        populate(certId, record);
        assertThat(lookup.findStatus(certId)).isPresent();

        evictor.evict(certId);
        assertThat(lookup.findStatus(certId)).isEmpty();
    }

    @Test
    void shouldEvictAll() {
        CacheEvictor evictor = createEvictor();
        StatusLookup lookup = asLookup();

        CertId certId1 = new CertId(new byte[]{1}, new byte[]{2}, new byte[]{3});
        CertId certId2 = new CertId(new byte[]{4}, new byte[]{5}, new byte[]{6});
        populate(certId1, new CertificateStatusRecord(certId1.issuerNameHash(), certId1.issuerKeyHash(), certId1.serialNumber(), com.company.incert.ocsp.shared.domain.CertificateStatus.GOOD, null, null, java.time.Instant.now(), "e1", 1));
        populate(certId2, new CertificateStatusRecord(certId2.issuerNameHash(), certId2.issuerKeyHash(), certId2.serialNumber(), com.company.incert.ocsp.shared.domain.CertificateStatus.GOOD, null, null, java.time.Instant.now(), "e2", 1));

        evictor.evictAll();
        assertThat(lookup.findStatus(certId1)).isEmpty();
        assertThat(lookup.findStatus(certId2)).isEmpty();
    }
}

