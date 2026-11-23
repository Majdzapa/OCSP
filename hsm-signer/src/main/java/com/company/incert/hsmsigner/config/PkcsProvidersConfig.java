package com.company.incert.hsmsigner.config;

import com.company.incert.pkcs11j.provider.Pkcs11ProviderConfig;
import com.company.incert.pkcs11j.provider.PkcsProviders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Initializes {@link PkcsProviders} with every enabled PKCS#11 device in {@link HsmSignerProperties}.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class PkcsProvidersConfig {

    private final HsmSignerProperties properties;

    @Bean(destroyMethod = "close")
    public PkcsProviders pkcsProviders() {
        PkcsProviders providers = new PkcsProviders();
        for (HsmSignerProperties.ProviderEntry entry : properties.getProviders()) {
            if (!entry.isEnabled()) {
                log.info("Skipping disabled PKCS#11 provider '{}'", entry.getId());
                continue;
            }
            Pkcs11ProviderConfig cfg = new Pkcs11ProviderConfig(
                    entry.getId(),
                    entry.getLibraryPath(),
                    entry.getTokenLabel(),
                    entry.getSlotId(),
                    entry.getSlotListIndex(),
                    entry.getPin() != null ? entry.getPin().toCharArray() : new char[0],
                    entry.getPoolSize(),
                    entry.isPrehashInJvm()
            );
            providers.register(cfg);
        }
        if (properties.getDefaultProviderId() != null && !properties.getDefaultProviderId().isBlank()) {
            providers.setDefaultProviderId(properties.getDefaultProviderId());
        }
        log.info("HSM Signer initialized {} PKCS11J provider(s): {} (default={})",
                providers.listProviderIds().size(),
                providers.listProviderIds(),
                providers.getDefaultProviderId());
        return providers;
    }
}

