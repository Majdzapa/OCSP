package com.company.incert.ocsp.admin.config;

import com.company.incert.ocsp.admin.application.service.AdminDashboardService;
import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
import com.company.incert.ocsp.status.application.port.out.OcspResponseCachePort;
import com.company.incert.ocsp.status.application.port.out.StatusStatsPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AdminConfig {

    @Bean
    public AdminDashboardService adminDashboardService(
            StatusStatsPort statusStatsPort,
            OcspSigner ocspSigner,
            OcspResponseCachePort responseCachePort) {
        return new AdminDashboardService(statusStatsPort, ocspSigner, responseCachePort);
    }
}

