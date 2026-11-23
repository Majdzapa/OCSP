package com.company.incert.ocsp.signing.config;

import com.company.incert.ocsp.signing.provider.PkcsProviders;

/**
 * Open-Closed extension point for loading signing providers into {@link PkcsProviders}
 * for a given {@code hsm.mode}.
 */
public interface CryptoProviderLoader {

    boolean supports(String mode);

    void loadInto(PkcsProviders registry, HsmProperties properties);
}

