package com.company.incert.ocsp.status.application.port.out;

import com.company.incert.ocsp.shared.domain.CertId;

/** Driven port: evict a cached OCSP response from L1 cache. */
public interface CacheEvictor {
    void evict(CertId certId);
    void evictAll();
}

