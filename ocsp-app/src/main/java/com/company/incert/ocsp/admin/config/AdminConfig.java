package com.company.incert.ocsp.admin.config;

import com.company.incert.ocsp.admin.application.service.AdminDashboardService;
import com.company.incert.ocsp.responder.application.port.in.HandleOcspRequestUseCase;
import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
import com.company.incert.ocsp.status.application.port.out.OcspResponseCachePort;
import com.company.incert.ocsp.status.application.port.out.StatusStatsPort;
import com.company.incert.ocsp.sync.application.port.in.ReconciliationUseCase;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AdminConfig {

    @Bean
    public AdminDashboardService adminDashboardService(
            StatusStatsPort statusStatsPort,
            OcspSigner ocspSigner,
            OcspResponseCachePort responseCachePort,
            HandleOcspRequestUseCase handleOcspRequestUseCase,
            ReconciliationUseCase reconciliationUseCase) {
        return new AdminDashboardService(
                statusStatsPort,
                ocspSigner,
                responseCachePort,
                handleOcspRequestUseCase,
                reconciliationUseCase
        );
    }
}

