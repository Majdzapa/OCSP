package com.company.incert.ocsp.signing.config;

import com.company.incert.ocsp.signing.hsm.Pkcs11OcspSigner;
import com.company.incert.ocsp.signing.hsm.SunPkcs11CryptoProviderAdapter;
import com.company.incert.ocsp.signing.provider.PkcsProviders;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Loads the primary local {@code SunPKCS11} device when {@code hsm.mode=SUN_PKCS11}.
 */
@Slf4j
@Component
@Order(20)
public class SunPkcs11CryptoProviderLoader implements CryptoProviderLoader {

    @Override
    public boolean supports(String mode) {
        return mode == null || mode.isBlank() || "SUN_PKCS11".equalsIgnoreCase(mode);
    }

    @Override
    public void loadInto(PkcsProviders registry, HsmProperties hsm) {
        String primaryId = (hsm.getDefaultProviderId() != null && !hsm.getDefaultProviderId().isBlank())
                ? hsm.getDefaultProviderId().trim()
                : "default";
        log.info("Connecting local SunPKCS11 provider '{}': library={}, token={}, slotIndex={}",
                primaryId, hsm.getPkcs11Library(), hsm.getTokenLabel(), hsm.getSlotIndex());
        Pkcs11OcspSigner primary = new Pkcs11OcspSigner(
                hsm.getPkcs11Library(), hsm.getTokenLabel(), hsm.getPin(),
                hsm.getKeyLabel(), hsm.getSlotIndex(), hsm.getConfigPath());
        registry.register(new SunPkcs11CryptoProviderAdapter(primaryId, primary));
    }
}

