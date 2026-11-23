package com.company.incert.ocsp.signing.provider;

import com.company.incert.ocsp.signing.pkcs11.Pkcs11Engine;
import com.company.incert.ocsp.signing.port.CryptoDeviceSpec;
import com.company.incert.ocsp.signing.port.CryptoProviderPort;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/**
 * {@link CryptoDeviceAdapterFactory} creating in-process {@code PKCS11J} adapters backed by
 * {@code org.xipki:ipkcs11wrapper} and {@link LibraryPathAllowlist}.
 */
@Component
public class Pkcs11jDeviceAdapterFactory implements CryptoDeviceAdapterFactory {

    private final Pkcs11Engine pkcs11Engine;
    private final LibraryPathAllowlist allowlist;

    public Pkcs11jDeviceAdapterFactory(
            @Qualifier("pkcs11Engine") Pkcs11Engine pkcs11Engine,
            LibraryPathAllowlist allowlist) {
        this.pkcs11Engine = pkcs11Engine;
        this.allowlist = allowlist;
    }

    @Override
    public boolean supports(String wrapperType) {
        return wrapperType == null || wrapperType.isBlank() || "PKCS11J".equalsIgnoreCase(wrapperType.trim());
    }

    @Override
    public CryptoProviderPort create(CryptoDeviceSpec spec) {
        return new Pkcs11jCryptoProviderAdapter(spec, pkcs11Engine, allowlist);
    }
}
