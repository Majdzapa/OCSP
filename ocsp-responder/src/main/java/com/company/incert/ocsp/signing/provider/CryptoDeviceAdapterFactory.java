package com.company.incert.ocsp.signing.provider;

import com.company.incert.ocsp.signing.port.CryptoDeviceSpec;
import com.company.incert.ocsp.signing.port.CryptoProviderPort;

/**
 * Open-Closed factory port mapping a {@code wrapperType} (e.g. {@code PKCS11J} or custom
 * {@code CryptoDeviceAdapterFactory} Spring beans such as KMS/KMIP)
 * to a runtime {@link CryptoProviderPort} instance initialized in {@code LOCKED} state.
 */
public interface CryptoDeviceAdapterFactory {

    boolean supports(String wrapperType);

    CryptoProviderPort create(CryptoDeviceSpec spec);
}

