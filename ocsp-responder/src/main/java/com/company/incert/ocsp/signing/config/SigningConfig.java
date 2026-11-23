package com.company.incert.ocsp.signing.config;

import com.company.incert.ocsp.signing.hsm.MultiProviderOcspSigner;
import com.company.incert.ocsp.signing.hsm.OcspSigner;
import com.company.incert.ocsp.signing.hsm.SoftwareFallbackSignerFactory;
import com.company.incert.ocsp.signing.provider.PkcsProviders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.security.Security;
import java.util.List;

/**
 * Composes {@link PkcsProviders} and {@link OcspSigner} via Open-Closed {@link CryptoProviderLoader} strategies.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class SigningConfig {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final HsmProperties hsm;
    private final List<CryptoProviderLoader> loaders;

    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true", matchIfMissing = true)
    public PkcsProviders pkcsProviders() {
        PkcsProviders providers = new PkcsProviders();
        String mode = hsm.getMode() != null ? hsm.getMode().trim().toUpperCase() : "SUN_PKCS11";

        List<CryptoProviderLoader> matching = loaders.stream()
                .filter(loader -> loader.supports(mode))
                .toList();
        if (matching.isEmpty()) {
            throw new IllegalStateException("No CryptoProviderLoader registered for hsm.mode=" + mode);
        }
        matching.forEach(loader -> loader.loadInto(providers, hsm));

        if (hsm.getDefaultProviderId() != null && !hsm.getDefaultProviderId().isBlank()
                && providers.listProviderIds().contains(hsm.getDefaultProviderId().trim())) {
            providers.setDefaultProviderId(hsm.getDefaultProviderId().trim());
        }

        log.info("PkcsProviders ready with {} device(s): {} (default={})",
                providers.listProviderIds().size(),
                providers.listProviderIds(),
                providers.getDefaultProviderId());
        return providers;
    }

    @Bean
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true", matchIfMissing = true)
    public OcspSigner multiProviderOcspSigner(PkcsProviders pkcsProviders) {
        return new MultiProviderOcspSigner(pkcsProviders, hsm.getKeyLabel());
    }

    @Bean
    @Profile("!prod")
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "false")
    public OcspSigner softwareSigner() {
        log.info("HSM disabled by configuration; using software signer.");
        return SoftwareFallbackSignerFactory.create();
    }
}
