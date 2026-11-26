package lu.incert.ocsp.signing.service;

import lu.incert.ocsp.signing.config.DatabaseCryptoProviderLoader;
import lu.incert.ocsp.signing.dto.CryptoDeviceDto;
import lu.incert.ocsp.signing.dto.CryptoDeviceRequest;
import lu.incert.ocsp.signing.dto.CryptoProviderDto;
import lu.incert.ocsp.signing.dto.CryptoProviderRequest;
import lu.incert.ocsp.signing.dto.CryptoSlotDto;
import lu.incert.ocsp.signing.dto.InitializeTokenRequest;
import lu.incert.ocsp.signing.dto.InitializeTokenResponse;
import lu.incert.ocsp.signing.entity.CryptoDeviceEntity;
import lu.incert.ocsp.signing.entity.CryptoProviderEntity;
import lu.incert.ocsp.signing.port.CryptoDeviceSpec;
import lu.incert.ocsp.signing.port.CryptoProviderPort;
import lu.incert.ocsp.signing.port.DeviceActivationState;
import lu.incert.ocsp.signing.port.DiscoveredSlotInfo;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import lu.incert.ocsp.signing.provider.CryptoDeviceAdapterFactory;
import lu.incert.ocsp.signing.provider.LibraryPathAllowlist;
import lu.incert.ocsp.signing.provider.PkcsProviders;
import lu.incert.ocsp.signing.repository.CryptoDeviceRepository;
import lu.incert.ocsp.signing.repository.CryptoProviderRepository;
import lu.incert.ocsp.signing.repository.SigningCertificateRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Manages DB-persisted cryptographic drivers ({@code crypto_providers}) and HSM devices
 * ({@code crypto_devices}) together with Pattern 2 Runtime Activation ({@code unlock} / {@code lock})
 * inside {@link PkcsProviders}. Zero PINs are ever persisted or logged.
 */
@Slf4j
@Service
public class CryptoDeviceService {

    private final CryptoProviderRepository providerRepository;
    private final CryptoDeviceRepository deviceRepository;
    private final SigningCertificateRepository signingCertificateRepository;
    private final List<CryptoDeviceAdapterFactory> adapterFactories;
    private final LibraryPathAllowlist allowlist;
    private final PkcsProviders pkcsProviders;

    @Autowired
    public CryptoDeviceService(
            CryptoProviderRepository providerRepository,
            CryptoDeviceRepository deviceRepository,
            SigningCertificateRepository signingCertificateRepository,
            List<CryptoDeviceAdapterFactory> adapterFactories,
            LibraryPathAllowlist allowlist,
            @Autowired(required = false) PkcsProviders pkcsProviders) {
        this.providerRepository = providerRepository;
        this.deviceRepository = deviceRepository;
        this.signingCertificateRepository = signingCertificateRepository;
        this.adapterFactories = adapterFactories != null ? adapterFactories : List.of();
        this.allowlist = allowlist;
        this.pkcsProviders = pkcsProviders;
    }

    // ---- Provider CRUD ----

    @Transactional(readOnly = true)
    public List<CryptoProviderDto> listProviders() {
        return providerRepository.findAllByOrderByIdAsc().stream()
                .map(this::toProviderDto)
                .toList();
    }

    public List<String> listAllowedLibraryDirs() {
        return allowlist.getAllowedDirectories();
    }

    @Transactional(readOnly = true)
    public List<CryptoSlotDto> discoverProviderSlots(Long providerId) {
        CryptoProviderEntity provider = providerRepository.findById(providerId)
                .orElseThrow(() -> new IllegalArgumentException("Crypto provider not found: " + providerId));
        String validatedLibrary = allowlist.validateLibraryPath(provider.getLibraryPath());
        String validatedWrapper = allowlist.validateWrapperPath(provider.getLibraryWrapperPath());
        CryptoDeviceAdapterFactory factory = requireFactory(provider.getWrapperType());

        List<DiscoveredSlotInfo> slots = factory.discoverSlots(validatedLibrary, validatedWrapper);
        List<CryptoDeviceEntity> existingDevices = deviceRepository.findAllByProviderId(provider.getId());

        return slots.stream()
                .map(slot -> toSlotDto(slot, existingDevices, provider))
                .toList();
    }

    /**
     * Initializes a PKCS#11 token / creates a new virtual slot (Vslot) via {@code C_InitToken} + {@code C_InitPIN}
     * and optionally registers it as a Pattern 2 {@code LOCKED} OCSP crypto device. Zero PINs are ever stored.
     */
    @Transactional
    public InitializeTokenResponse initializeProviderToken(
            Long providerId,
            InitializeTokenRequest request,
            char[] soPin,
            char[] userPin) {
        try {
            CryptoProviderEntity provider = providerRepository.findById(providerId)
                    .orElseThrow(() -> new IllegalArgumentException("Crypto provider not found: " + providerId));
            String validatedLibrary = allowlist.validateLibraryPath(provider.getLibraryPath());
            String validatedWrapper = allowlist.validateWrapperPath(provider.getLibraryWrapperPath());
            CryptoDeviceAdapterFactory factory = requireFactory(provider.getWrapperType());

            String cleanLabel = requireCleanId(request.tokenLabel(), "tokenLabel");
            if (cleanLabel.length() > 32) {
                throw new IllegalArgumentException("tokenLabel must be at most 32 characters (PKCS#11 limit)");
            }

            DiscoveredSlotInfo initialized = factory.initializeToken(
                    validatedLibrary,
                    validatedWrapper,
                    request.slotId(),
                    cleanLabel,
                    soPin,
                    userPin
            );

            CryptoDeviceDto registeredDevice = null;
            if (Boolean.TRUE.equals(request.registerAsDevice())) {
                String deviceId = (request.deviceId() != null && !request.deviceId().isBlank())
                        ? request.deviceId().trim()
                        : suggestDeviceId(provider.getCode(), initialized.tokenLabel(), initialized.slotId());
                int poolSize = (request.poolSize() != null && request.poolSize() > 0) ? request.poolSize() : 4;
                registeredDevice = createDevice(new CryptoDeviceRequest(
                        deviceId,
                        provider.getId(),
                        initialized.tokenLabel(),
                        // Resolve by tokenLabel so SoftHSM2's post-C_Finalize slotId reassignment never breaks unlock
                        (initialized.tokenLabel() != null && !initialized.tokenLabel().isBlank()) ? null : initialized.slotId(),
                        initialized.slotListIndex(),
                        poolSize,
                        false,
                        Boolean.TRUE.equals(request.isDefault()),
                        true
                ));
            }

            List<CryptoDeviceEntity> existingDevices = deviceRepository.findAllByProviderId(provider.getId());
            CryptoSlotDto slotDto = toSlotDto(initialized, existingDevices, provider);
            String msg = registeredDevice != null
                    ? "Token '" + initialized.tokenLabel() + "' initialized on slot " + initialized.slotId()
                        + " and registered as LOCKED device '" + registeredDevice.deviceId()
                        + "' (unlock with User PIN to activate)."
                    : "Token '" + initialized.tokenLabel() + "' initialized cleanly on slot " + initialized.slotId()
                        + " (PINs wiped from memory).";
            log.info("Initialized token '{}' on provider '{}' slot {} (registeredDevice={})",
                    initialized.tokenLabel(), provider.getCode(), initialized.slotId(),
                    registeredDevice != null ? registeredDevice.deviceId() : "none");
            return new InitializeTokenResponse(slotDto, registeredDevice, msg);
        } finally {
            if (soPin != null) {
                Arrays.fill(soPin, '\0');
            }
            if (userPin != null) {
                Arrays.fill(userPin, '\0');
            }
        }
    }

    private static String suggestDeviceId(String providerCode, String tokenLabel, long slotId) {
        String base = (tokenLabel != null && !tokenLabel.isBlank()) ? tokenLabel : ("slot-" + slotId);
        String slug = base.toLowerCase().replaceAll("[^a-z0-9-]+", "-").replaceAll("^-+|-+$", "");
        if (slug.isEmpty()) {
            slug = "slot-" + slotId;
        }
        String candidate = (providerCode != null && !providerCode.isBlank()) ? (providerCode + "-" + slug) : slug;
        return candidate.length() > 95 ? candidate.substring(0, 95) : candidate;
    }

    private CryptoSlotDto toSlotDto(
            DiscoveredSlotInfo slot,
            List<CryptoDeviceEntity> existingDevices,
            CryptoProviderEntity provider) {
        CryptoDeviceEntity matched = existingDevices.stream()
                .filter(d -> matchesSlot(d, slot))
                .findFirst()
                .orElse(null);

        String configuredDeviceId = matched != null ? matched.getDeviceId() : null;
        String configuredDeviceState = matched != null ? resolveConfiguredState(matched, provider) : null;
        return new CryptoSlotDto(
                slot.slotId(),
                slot.slotListIndex(),
                slot.tokenLabel(),
                slot.manufacturerId(),
                slot.model(),
                slot.serialNumber(),
                slot.initialized(),
                configuredDeviceId,
                configuredDeviceState
        );
    }

    private static boolean matchesSlot(CryptoDeviceEntity device, DiscoveredSlotInfo slot) {
        if (device.getSlotId() != null) {
            return device.getSlotId().equals(slot.slotId());
        }
        if (device.getTokenLabel() != null && !device.getTokenLabel().isBlank()) {
            return slot.tokenLabel() != null && device.getTokenLabel().trim().equals(slot.tokenLabel().trim());
        }
        return device.getSlotListIndex() == slot.slotListIndex();
    }

    private String resolveConfiguredState(CryptoDeviceEntity device, CryptoProviderEntity provider) {
        if (!device.isEnabled() || !provider.isEnabled()) {
            return "DISABLED";
        }
        if (pkcsProviders != null && pkcsProviders.hasProvider(device.getDeviceId())) {
            return pkcsProviders.getProvider(device.getDeviceId()).getDeviceInfo().activationState();
        }
        return DeviceActivationState.LOCKED.name();
    }

    @Transactional
    public CryptoProviderDto createProvider(CryptoProviderRequest request) {
        String code = requireCleanId(request.code(), "Provider code");
        if (providerRepository.existsByCode(code)) {
            throw new IllegalArgumentException("Crypto provider with code '" + code + "' already exists");
        }
        String wrapperType = normalizeWrapperType(request.wrapperType());
        requireFactory(wrapperType);
        String validatedLibrary = allowlist.validateLibraryPath(request.libraryPath());
        String validatedWrapper = allowlist.validateWrapperPath(request.libraryWrapperPath());

        CryptoProviderEntity entity = CryptoProviderEntity.builder()
                .code(code)
                .name(request.name().trim())
                .wrapperType(wrapperType)
                .libraryPath(validatedLibrary)
                .libraryWrapperPath(validatedWrapper)
                .enabled(request.enabled() == null || request.enabled())
                .build();

        CryptoProviderEntity saved = providerRepository.save(entity);
        log.info("Created crypto provider '{}' (wrapper={}, library={}, wrapperPath={})",
                saved.getCode(), saved.getWrapperType(), saved.getLibraryPath(), saved.getLibraryWrapperPath());
        return toProviderDto(saved);
    }

    @Transactional
    public CryptoProviderDto updateProvider(Long id, CryptoProviderRequest request) {
        CryptoProviderEntity entity = providerRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Crypto provider not found: " + id));

        String newCode = requireCleanId(request.code(), "Provider code");
        if (!newCode.equals(entity.getCode()) && providerRepository.existsByCode(newCode)) {
            throw new IllegalArgumentException("Crypto provider with code '" + newCode + "' already exists");
        }
        String wrapperType = normalizeWrapperType(request.wrapperType());
        requireFactory(wrapperType);
        String validatedLibrary = allowlist.validateLibraryPath(request.libraryPath());
        String validatedWrapper = allowlist.validateWrapperPath(request.libraryWrapperPath());
        boolean newEnabled = request.enabled() == null || request.enabled();

        boolean runtimeChanged = !wrapperType.equals(entity.getWrapperType())
                || !validatedLibrary.equals(entity.getLibraryPath())
                || !validatedWrapper.equals(entity.getLibraryWrapperPath())
                || newEnabled != entity.isEnabled()
                || !newCode.equals(entity.getCode());

        entity.setCode(newCode);
        entity.setName(request.name().trim());
        entity.setWrapperType(wrapperType);
        entity.setLibraryPath(validatedLibrary);
        entity.setLibraryWrapperPath(validatedWrapper);
        entity.setEnabled(newEnabled);

        CryptoProviderEntity saved = providerRepository.save(entity);
        if (runtimeChanged) {
            for (CryptoDeviceEntity dev : deviceRepository.findAllByProviderId(saved.getId())) {
                syncRuntimeDevice(dev, saved);
            }
        }
        log.info("Updated crypto provider id={} code='{}' (runtimeRefreshed={})", saved.getId(), saved.getCode(), runtimeChanged);
        return toProviderDto(saved);
    }

    @Transactional
    public void deleteProvider(Long id) {
        CryptoProviderEntity entity = providerRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Crypto provider not found: " + id));
        if (deviceRepository.existsByProviderId(id)) {
            throw new IllegalStateException(
                    "Cannot delete crypto provider '" + entity.getCode() + "' while devices reference it");
        }
        providerRepository.delete(entity);
        log.info("Deleted crypto provider id={} code='{}'", id, entity.getCode());
    }

    // ---- Device CRUD & Pattern 2 Runtime Activation ----

    @Transactional(readOnly = true)
    public List<CryptoDeviceDto> listDevices() {
        return deviceRepository.findAllByOrderByIdAsc().stream()
                .map(this::toDeviceDto)
                .toList();
    }

    @Transactional
    public CryptoDeviceDto createDevice(CryptoDeviceRequest request) {
        String deviceId = requireCleanDeviceId(request.deviceId());
        if (deviceRepository.existsByDeviceId(deviceId)) {
            throw new IllegalArgumentException("Crypto device '" + deviceId + "' already exists");
        }
        CryptoProviderEntity provider = providerRepository.findById(request.providerId())
                .orElseThrow(() -> new IllegalArgumentException("Crypto provider not found: " + request.providerId()));

        boolean makeDefault = Boolean.TRUE.equals(request.isDefault());
        if (makeDefault) {
            clearExistingDefaultDevices(null);
        }

        CryptoDeviceEntity entity = CryptoDeviceEntity.builder()
                .deviceId(deviceId)
                .provider(provider)
                .tokenLabel(blankToNull(request.tokenLabel()))
                .slotId(request.slotId())
                .slotListIndex(request.slotListIndex() != null ? request.slotListIndex() : 0)
                .poolSize(request.poolSize() != null ? request.poolSize() : 4)
                .prehashInJvm(Boolean.TRUE.equals(request.prehashInJvm()))
                .defaultDevice(makeDefault)
                .enabled(request.enabled() == null || request.enabled())
                .build();

        CryptoDeviceEntity saved = deviceRepository.save(entity);
        syncRuntimeDevice(saved, provider);
        log.info("Created crypto device '{}' referencing provider '{}' in LOCKED state",
                saved.getDeviceId(), provider.getCode());
        return toDeviceDto(saved);
    }

    @Transactional
    public CryptoDeviceDto updateDevice(Long id, CryptoDeviceRequest request) {
        CryptoDeviceEntity entity = deviceRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Crypto device not found: " + id));

        String oldDeviceId = entity.getDeviceId();
        String newDeviceId = requireCleanDeviceId(request.deviceId());
        if (!newDeviceId.equals(oldDeviceId)) {
            if (deviceRepository.existsByDeviceId(newDeviceId)) {
                throw new IllegalArgumentException("Crypto device '" + newDeviceId + "' already exists");
            }
            if (signingCertificateRepository.existsByProviderIdAndActiveTrue(oldDeviceId)) {
                throw new IllegalStateException(
                        "Cannot rename device '" + oldDeviceId + "' while an active signing certificate references it");
            }
        }

        CryptoProviderEntity provider = providerRepository.findById(request.providerId())
                .orElseThrow(() -> new IllegalArgumentException("Crypto provider not found: " + request.providerId()));

        String newTokenLabel = blankToNull(request.tokenLabel());
        int newSlotListIndex = request.slotListIndex() != null ? request.slotListIndex() : 0;
        int newPoolSize = request.poolSize() != null ? request.poolSize() : 4;
        boolean newPrehash = Boolean.TRUE.equals(request.prehashInJvm());
        boolean newEnabled = request.enabled() == null || request.enabled();
        boolean makeDefault = Boolean.TRUE.equals(request.isDefault());

        boolean runtimeConfigChanged = !newDeviceId.equals(oldDeviceId)
                || !Objects.equals(provider.getId(), entity.getProvider().getId())
                || !Objects.equals(newTokenLabel, entity.getTokenLabel())
                || !Objects.equals(request.slotId(), entity.getSlotId())
                || newSlotListIndex != entity.getSlotListIndex()
                || newPoolSize != entity.getPoolSize()
                || newPrehash != entity.isPrehashInJvm()
                || newEnabled != entity.isEnabled();

        if (makeDefault) {
            clearExistingDefaultDevices(id);
        }

        entity.setDeviceId(newDeviceId);
        entity.setProvider(provider);
        entity.setTokenLabel(newTokenLabel);
        entity.setSlotId(request.slotId());
        entity.setSlotListIndex(newSlotListIndex);
        entity.setPoolSize(newPoolSize);
        entity.setPrehashInJvm(newPrehash);
        entity.setDefaultDevice(makeDefault);
        entity.setEnabled(newEnabled);

        CryptoDeviceEntity saved = deviceRepository.save(entity);
        if (pkcsProviders != null) {
            if (!newDeviceId.equals(oldDeviceId)) {
                pkcsProviders.unregister(oldDeviceId);
            }
            if (runtimeConfigChanged || !pkcsProviders.hasProvider(saved.getDeviceId())) {
                syncRuntimeDevice(saved, provider);
            } else if (saved.isDefaultDevice()) {
                pkcsProviders.setDefaultProviderId(saved.getDeviceId());
            }
        }
        log.info("Updated crypto device id={} deviceId='{}' (runtimeConfigChanged={})",
                saved.getId(), saved.getDeviceId(), runtimeConfigChanged);
        return toDeviceDto(saved);
    }

    @Transactional
    public void deleteDevice(Long id) {
        CryptoDeviceEntity entity = deviceRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Crypto device not found: " + id));
        if (signingCertificateRepository.existsByProviderIdAndActiveTrue(entity.getDeviceId())) {
            throw new IllegalStateException(
                    "Cannot delete crypto device '" + entity.getDeviceId()
                            + "' while an active signing certificate references it");
        }
        if (pkcsProviders != null) {
            pkcsProviders.unregister(entity.getDeviceId());
        }
        deviceRepository.delete(entity);
        log.info("Deleted crypto device id={} deviceId='{}'", id, entity.getDeviceId());
    }

    public CryptoDeviceDto activateDevice(String deviceId, char[] pin) {
        try {
            if (pkcsProviders == null) {
                throw new IllegalStateException("HSM signing is disabled (hsm.enabled=false)");
            }
            String cleanId = requireCleanDeviceId(deviceId);
            CryptoDeviceEntity entity = deviceRepository.findByDeviceId(cleanId)
                    .orElseThrow(() -> new IllegalArgumentException("Crypto device not found: " + cleanId));
            CryptoProviderEntity provider = entity.getProvider();
            if (!entity.isEnabled() || provider == null || !provider.isEnabled()) {
                throw new IllegalStateException("Cannot unlock disabled crypto device '" + cleanId + "'");
            }
            if (!pkcsProviders.hasProvider(cleanId)) {
                syncRuntimeDevice(entity, provider);
            }
            pkcsProviders.activate(cleanId, pin);
            if (entity.isDefaultDevice()) {
                pkcsProviders.setDefaultProviderId(cleanId);
            }
            return toDeviceDto(entity);
        } finally {
            if (pin != null) {
                Arrays.fill(pin, '\0');
            }
        }
    }

    public CryptoDeviceDto deactivateDevice(String deviceId) {
        if (pkcsProviders == null) {
            throw new IllegalStateException("HSM signing is disabled (hsm.enabled=false)");
        }
        String cleanId = requireCleanDeviceId(deviceId);
        CryptoDeviceEntity entity = deviceRepository.findByDeviceId(cleanId)
                .orElseThrow(() -> new IllegalArgumentException("Crypto device not found: " + cleanId));
        if (pkcsProviders.hasProvider(cleanId)) {
            pkcsProviders.deactivate(cleanId);
        }
        return toDeviceDto(entity);
    }

    // ---- Helpers ----

    private void syncRuntimeDevice(CryptoDeviceEntity device, CryptoProviderEntity provider) {
        if (pkcsProviders == null) {
            return;
        }
        if (!device.isEnabled() || provider == null || !provider.isEnabled()) {
            pkcsProviders.unregister(device.getDeviceId());
            return;
        }
        CryptoDeviceSpec spec = DatabaseCryptoProviderLoader.toSpec(device, provider);
        CryptoDeviceAdapterFactory factory = requireFactory(spec.wrapperType());
        pkcsProviders.replace(factory.create(spec));
        if (device.isDefaultDevice()) {
            pkcsProviders.setDefaultProviderId(device.getDeviceId());
        }
    }

    private void clearExistingDefaultDevices(Long exceptId) {
        for (CryptoDeviceEntity existing : deviceRepository.findAll()) {
            if (existing.isDefaultDevice() && !Objects.equals(existing.getId(), exceptId)) {
                existing.setDefaultDevice(false);
                deviceRepository.save(existing);
            }
        }
    }

    private CryptoDeviceAdapterFactory requireFactory(String wrapperType) {
        return adapterFactories.stream()
                .filter(f -> f.supports(wrapperType))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unsupported wrapperType '" + wrapperType + "'. No CryptoDeviceAdapterFactory registered."));
    }

    private CryptoProviderDto toProviderDto(CryptoProviderEntity e) {
        return new CryptoProviderDto(
                e.getId(),
                e.getCode(),
                e.getName(),
                e.getWrapperType(),
                e.getLibraryPath(),
                e.getLibraryWrapperPath(),
                e.isEnabled(),
                deviceRepository.countByProviderId(e.getId()),
                e.getCreatedAt(),
                e.getUpdatedAt()
        );
    }

    private CryptoDeviceDto toDeviceDto(CryptoDeviceEntity entity) {
        CryptoProviderEntity p = entity.getProvider();
        String activationState = DeviceActivationState.LOCKED.name();
        boolean healthy = false;
        String statusMessage = entity.isEnabled() && p.isEnabled()
                ? "LOCKED — awaiting runtime PIN unlock"
                : "DISABLED";
        List<String> keyLabels = List.of();
        Map<String, String> keyAlgorithms = Map.of();
        Long resolvedSlotId = entity.getSlotId();
        String resolvedTokenLabel = entity.getTokenLabel();

        if (pkcsProviders != null && pkcsProviders.hasProvider(entity.getDeviceId())) {
            CryptoProviderPort port = pkcsProviders.getProvider(entity.getDeviceId());
            ProviderDeviceInfo info = port.getDeviceInfo();
            activationState = info.activationState();
            healthy = info.healthy();
            statusMessage = info.statusMessage();
            keyLabels = info.keyLabels() != null ? info.keyLabels() : List.of();
            keyAlgorithms = info.keyAlgorithms() != null ? info.keyAlgorithms() : Map.of();
            if (resolvedSlotId == null && healthy) {
                resolvedSlotId = info.slotId();
            }
            if ((resolvedTokenLabel == null || resolvedTokenLabel.isBlank()) && info.tokenLabel() != null && !info.tokenLabel().isBlank()) {
                resolvedTokenLabel = info.tokenLabel();
            }
        }

        return new CryptoDeviceDto(
                entity.getId(),
                entity.getDeviceId(),
                p.getId(),
                p.getCode(),
                p.getName(),
                p.getWrapperType(),
                p.getLibraryPath(),
                p.getLibraryWrapperPath(),
                resolvedTokenLabel,
                resolvedSlotId,
                entity.getSlotListIndex(),
                entity.getPoolSize(),
                entity.isPrehashInJvm(),
                entity.isDefaultDevice(),
                entity.isEnabled(),
                activationState,
                healthy,
                statusMessage,
                keyLabels,
                keyAlgorithms,
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }

    private static String normalizeWrapperType(String wrapperType) {
        if (wrapperType == null || wrapperType.isBlank()) {
            return "PKCS11J";
        }
        return wrapperType.trim().toUpperCase();
    }

    private static String requireCleanDeviceId(String value) {
        String clean = requireCleanId(value, "deviceId");
        if ("default".equalsIgnoreCase(clean)) {
            throw new IllegalArgumentException("deviceId 'default' is reserved");
        }
        return clean;
    }

    private static String requireCleanId(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value.trim();
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }
}
