package lu.incert.ocsp.signing.config;

import lu.incert.ocsp.signing.entity.CryptoDeviceEntity;
import lu.incert.ocsp.signing.entity.CryptoProviderEntity;
import lu.incert.ocsp.signing.port.CryptoDeviceSpec;
import lu.incert.ocsp.signing.provider.CryptoDeviceAdapterFactory;
import lu.incert.ocsp.signing.provider.PkcsProviders;
import lu.incert.ocsp.signing.repository.CryptoDeviceRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Loads DB-configured cryptographic providers and devices ({@code crypto_providers} + {@code crypto_devices})
 * into {@link PkcsProviders} in {@code LOCKED} state (Pattern 2 Runtime Activation — zero PINs in DB).
 */
@Slf4j
@Component
@Order(10)
@RequiredArgsConstructor
public class DatabaseCryptoProviderLoader implements CryptoProviderLoader {

    private final CryptoDeviceRepository deviceRepository;
    private final List<CryptoDeviceAdapterFactory> adapterFactories;

    @Override
    public boolean supports(String mode) {
        return mode == null || mode.isBlank()
                || "DATABASE".equalsIgnoreCase(mode.trim())
                || "PKCS11J".equalsIgnoreCase(mode.trim());
    }

    @Override
    public void loadInto(PkcsProviders registry, HsmProperties hsm) {
        List<CryptoDeviceEntity> enabledDevices = deviceRepository.findAllByEnabledTrueOrderByIdAsc();
        String chosenDefault = null;

        for (CryptoDeviceEntity device : enabledDevices) {
            CryptoProviderEntity provider = device.getProvider();
            if (provider == null || !provider.isEnabled()) {
                log.info("Skipping DB crypto device '{}' because provider '{}' is disabled",
                        device.getDeviceId(), provider != null ? provider.getCode() : "null");
                continue;
            }
            CryptoDeviceSpec spec = toSpec(device, provider);
            CryptoDeviceAdapterFactory factory = adapterFactories.stream()
                    .filter(f -> f.supports(spec.wrapperType()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException(
                            "No CryptoDeviceAdapterFactory found for wrapperType='" + spec.wrapperType() + "'"));

            registry.register(factory.create(spec));
            if (device.isDefaultDevice()) {
                chosenDefault = device.getDeviceId();
            }
            log.info("Registered DB crypto device '{}' (provider={}, wrapper={}, library={}, wrapperPath={}) in LOCKED state",
                    spec.deviceId(), spec.providerCode(), spec.wrapperType(), spec.libraryPath(), spec.libraryWrapperPath());
        }

        if (chosenDefault != null) {
            registry.setDefaultProviderId(chosenDefault);
        }
    }

    public static CryptoDeviceSpec toSpec(CryptoDeviceEntity device, CryptoProviderEntity provider) {
        return new CryptoDeviceSpec(
                device.getDeviceId(),
                provider.getCode(),
                provider.getWrapperType(),
                provider.getLibraryPath(),
                provider.getLibraryWrapperPath(),
                device.getTokenLabel(),
                device.getSlotId(),
                device.getSlotListIndex(),
                device.getPoolSize(),
                device.isPrehashInJvm()
        );
    }
}

