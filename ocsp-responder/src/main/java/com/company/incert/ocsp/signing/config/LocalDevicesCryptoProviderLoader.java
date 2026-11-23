package com.company.incert.ocsp.signing.config;

import com.company.incert.ocsp.signing.hsm.Pkcs11OcspSigner;
import com.company.incert.ocsp.signing.hsm.SunPkcs11CryptoProviderAdapter;
import com.company.incert.ocsp.signing.provider.PkcsProviders;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * Additive loader registering any optional extra {@code hsm.local-devices[]} alongside primary providers.
 */
@Component
@Order(100)
public class LocalDevicesCryptoProviderLoader implements CryptoProviderLoader {

    @Override
    public boolean supports(String mode) {
        return !"SOFTWARE".equalsIgnoreCase(mode);
    }

    @Override
    public void loadInto(PkcsProviders registry, HsmProperties hsm) {
        if (hsm.getLocalDevices() == null) {
            return;
        }
        for (HsmProperties.LocalDeviceProperties dev : hsm.getLocalDevices()) {
            if (!dev.isEnabled()) {
                continue;
            }
            if (dev.getId() == null || dev.getId().isBlank()) {
                throw new IllegalArgumentException("hsm.local-devices entries must specify a non-blank id");
            }
            Pkcs11OcspSigner signer = new Pkcs11OcspSigner(
                    dev.getPkcs11Library(),
                    dev.getTokenLabel(),
                    dev.getPin(),
                    dev.getKeyLabel(),
                    dev.getSlotIndex(),
                    dev.getConfigPath());
            registry.register(new SunPkcs11CryptoProviderAdapter(dev.getId().trim(), signer));
        }
    }
}

