package com.company.incert.ocsp.contract;

import com.company.incert.ocsp.shared.CertificateStatusRecord;
import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.status.adapter.out.cache.CaffeineStatusCacheAdapter;
import com.company.incert.ocsp.status.application.port.out.StatusLookup;
import com.github.benmanes.caffeine.cache.Caffeine;

public class CaffeineStatusCacheAdapterLookupContractTest extends StatusLookupContract {

    private CaffeineStatusCacheAdapter adapter;

    @Override
    protected StatusLookup createStatusLookup() {
        adapter = new CaffeineStatusCacheAdapter(Caffeine.newBuilder().build());
        return adapter;
    }

    @Override
    protected void populate(CertId certId, CertificateStatusRecord record) {
        adapter.put(certId, record);
    }
}

