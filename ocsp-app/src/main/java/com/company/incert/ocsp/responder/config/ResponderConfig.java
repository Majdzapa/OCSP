package com.company.incert.ocsp.responder.config;

import com.company.incert.ocsp.responder.application.port.in.HandleOcspRequestUseCase;
import com.company.incert.ocsp.responder.application.service.OcspRequestHandlerService;
import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
import com.company.incert.ocsp.status.application.port.in.LookupStatusUseCase;
import com.company.incert.ocsp.status.application.port.out.OcspResponseCachePort;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ResponderConfig {

    @Bean
    public HandleOcspRequestUseCase handleOcspRequestUseCase(
            LookupStatusUseCase statusLookup,
            OcspSigner ocspSigner,
            MeterRegistry meterRegistry,
            OcspResponseCachePort responseCachePort) {
        return new OcspRequestHandlerService(statusLookup, ocspSigner, meterRegistry, responseCachePort);
    }
}

