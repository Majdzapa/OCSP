package lu.incert.ocsp.signing.service;

import lu.incert.ocsp.signing.dto.AddSigningCertificateRequest;
import lu.incert.ocsp.signing.dto.GenerateCsrRequest;
import lu.incert.ocsp.signing.dto.GenerateCsrResponse;
import lu.incert.ocsp.signing.dto.SignerCertImportRequest;
import lu.incert.ocsp.signing.dto.SignerCsrRequest;
import lu.incert.ocsp.signing.dto.SignerDto;
import lu.incert.ocsp.signing.dto.SignerRequest;
import lu.incert.ocsp.signing.dto.SigningCertificateDto;
import lu.incert.ocsp.signing.entity.CryptoDeviceEntity;
import lu.incert.ocsp.signing.entity.CryptoProviderEntity;
import lu.incert.ocsp.signing.entity.OcspSignerEntity;
import lu.incert.ocsp.signing.entity.OcspSignerVslotEntity;
import lu.incert.ocsp.signing.entity.SigningCertificate;
import lu.incert.ocsp.signing.hsm.OcspSigner;
import lu.incert.ocsp.signing.hsm.SigningAlgorithm;
import lu.incert.ocsp.signing.port.DeviceActivationState;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import lu.incert.ocsp.signing.repository.CryptoDeviceRepository;
import lu.incert.ocsp.signing.repository.OcspSignerRepository;
import lu.incert.ocsp.signing.repository.SigningCertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Manages the lifecycle of first-class OCSP {@code Signer} aggregates ({@code ocsp_signers}),
 * including ordered HSM Vslots ({@code ocsp_signer_vslots}), key + CSR generation
 * ({@code POST/GET /signers/{id}/csr}), and X.509 certificate import/retrieval
 * ({@code POST/GET /signers/{id}/cert}).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OcspSignerManagementService {

    private final OcspSignerRepository signerRepository;
    private final CryptoDeviceRepository deviceRepository;
    private final SigningCertificateRepository signingCertRepository;
    private final SigningCertificateService signingCertificateService;
    private final OcspSigner ocspSigner;

    @Transactional(readOnly = true)
    public List<SignerDto> listAll() {
        Map<String, ProviderDeviceInfo> liveDevices = mapLiveDevices();
        return signerRepository.findAllByOrderByIdAsc().stream()
                .map(s -> toDto(s, liveDevices))
                .toList();
    }

    @Transactional(readOnly = true)
    public SignerDto getById(Long id) {
        OcspSignerEntity entity = requireSigner(id);
        return toDto(entity, mapLiveDevices());
    }

    @Transactional
    public SignerDto createSigner(SignerRequest request) {
        String cleanCode = requireClean(request.code(), "code");
        if (signerRepository.existsByCode(cleanCode)) {
            throw new IllegalArgumentException("Signer with code '" + cleanCode + "' already exists");
        }
        String keyAlg = normalizeKeyAlg(request.keyAlgorithm());
        int keySize = resolveKeySize(keyAlg, request.keySize());
        String sigAlg = validateSignatureAlgForKeyType(request.signatureAlgorithm(), keyAlg);

        List<CryptoDeviceEntity> orderedDevices = resolveVslotDevices(request.vslotDeviceIds());

        OcspSignerEntity signer = OcspSignerEntity.builder()
                .code(cleanCode)
                .name(requireClean(request.name(), "name"))
                .status("DRAFT")
                .subjectDn(requireClean(request.subjectDn(), "subjectDn"))
                .keyLabel(requireClean(request.keyLabel(), "keyLabel"))
                .keyAlgorithm(keyAlg)
                .keySize(keySize)
                .signatureAlgorithm(sigAlg)
                .active(false)
                .build();

        bindVslots(signer, orderedDevices);
        OcspSignerEntity saved = signerRepository.save(signer);
        log.info("Created OCSP Signer '{}' (id={}, keyLabel='{}', key={} {}, sigAlg={}, vslots={})",
                saved.getCode(), saved.getId(), saved.getKeyLabel(), saved.getKeyAlgorithm(),
                saved.getKeySize(), saved.getSignatureAlgorithm(),
                orderedDevices.stream().map(CryptoDeviceEntity::getDeviceId).toList());
        return toDto(saved, mapLiveDevices());
    }

    @Transactional
    public SignerDto updateSigner(Long id, SignerRequest request) {
        OcspSignerEntity signer = requireSigner(id);
        String cleanCode = requireClean(request.code(), "code");
        signerRepository.findByCode(cleanCode).ifPresent(existing -> {
            if (!existing.getId().equals(id)) {
                throw new IllegalArgumentException("Another signer already uses code '" + cleanCode + "'");
            }
        });

        String keyAlg = normalizeKeyAlg(request.keyAlgorithm());
        int keySize = resolveKeySize(keyAlg, request.keySize());
        String sigAlg = validateSignatureAlgForKeyType(request.signatureAlgorithm(), keyAlg);
        List<CryptoDeviceEntity> orderedDevices = resolveVslotDevices(request.vslotDeviceIds());

        signer.setCode(cleanCode);
        signer.setName(requireClean(request.name(), "name"));
        signer.setSubjectDn(requireClean(request.subjectDn(), "subjectDn"));
        signer.setKeyLabel(requireClean(request.keyLabel(), "keyLabel"));
        signer.setKeyAlgorithm(keyAlg);
        signer.setKeySize(keySize);
        signer.setSignatureAlgorithm(sigAlg);
        bindVslots(signer, orderedDevices);

        OcspSignerEntity saved = signerRepository.save(signer);
        if (saved.getSigningCertificateId() != null) {
            signingCertRepository.findById(saved.getSigningCertificateId()).ifPresent(sc -> {
                sc.setProviderId(orderedDevices.get(0).getDeviceId());
                sc.setKeyLabel(saved.getKeyLabel());
                sc.setSignatureAlgorithm(saved.getSignatureAlgorithm());
                signingCertRepository.save(sc);
            });
        }
        return toDto(saved, mapLiveDevices());
    }

    @Transactional
    public void deleteSigner(Long id) {
        OcspSignerEntity signer = requireSigner(id);
        if (signer.isActive()) {
            throw new IllegalStateException("Cannot delete an ACTIVE signer ('" + signer.getCode()
                    + "'). Deactivate it first.");
        }
        Long linkedCertId = signer.getSigningCertificateId();
        signerRepository.delete(signer);
        if (linkedCertId != null) {
            signingCertRepository.findById(linkedCertId).ifPresent(sc -> {
                if (!sc.isActive()) {
                    signingCertRepository.delete(sc);
                }
            });
        }
        log.info("Deleted OCSP Signer id={}, code='{}'", id, signer.getCode());
    }

    /**
     * Generates a non-extractable keypair (or reuses existing key) inside the signer's primary / first
     * active HSM Vslot, signs a PKCS#10 CSR with the verified signature algorithm, and stores {@code csrPem}.
     */
    @Transactional
    public SignerCsrRequest.SignerCsrResponse generateCsr(Long id, SignerCsrRequest request) {
        OcspSignerEntity signer = requireSigner(id);
        Map<String, ProviderDeviceInfo> liveDevices = mapLiveDevices();

        String targetVslot = resolveTargetVslotForCsr(signer, request != null ? request.vslotDeviceId() : null, liveDevices);
        String subjectDn = (request != null && request.subjectDn() != null && !request.subjectDn().isBlank())
                ? request.subjectDn().trim()
                : signer.getSubjectDn();
        String keyAlg = (request != null && request.keyAlgorithm() != null && !request.keyAlgorithm().isBlank())
                ? normalizeKeyAlg(request.keyAlgorithm())
                : signer.getKeyAlgorithm();
        int keySize = (request != null && request.keySize() != null)
                ? resolveKeySize(keyAlg, request.keySize())
                : signer.getKeySize();
        String sigAlg = (request != null && request.signatureAlgorithm() != null && !request.signatureAlgorithm().isBlank())
                ? validateSignatureAlgForKeyType(request.signatureAlgorithm(), keyAlg)
                : signer.getSignatureAlgorithm();

        // Auto-detect whether keyLabel already exists on targetVslot when reuseExistingKey is omitted
        ProviderDeviceInfo vslotInfo = liveDevices.get(targetVslot);
        boolean keyAlreadyOnToken = vslotInfo != null
                && vslotInfo.keyLabels() != null
                && vslotInfo.keyLabels().contains(signer.getKeyLabel());
        boolean reuse = (request != null && request.reuseExistingKey() != null)
                ? request.reuseExistingKey()
                : keyAlreadyOnToken;

        GenerateCsrResponse csrRes = signingCertificateService.generateCsr(new GenerateCsrRequest(
                signer.getKeyLabel(),
                subjectDn,
                keyAlg,
                keySize,
                reuse,
                targetVslot,
                sigAlg
        ));

        Instant now = Instant.now();
        signer.setSubjectDn(subjectDn);
        signer.setKeyAlgorithm(keyAlg);
        signer.setKeySize(keySize);
        signer.setSignatureAlgorithm(sigAlg);
        signer.setCsrPem(csrRes.csrPem());
        signer.setCsrGeneratedAt(now);
        if (!signer.isActive() && signer.getCertificatePem() == null) {
            signer.setStatus("CSR_GENERATED");
        }
        signerRepository.save(signer);

        log.info("Generated CSR for Signer '{}' (id={}) on Vslot '{}' (keyLabel='{}', key={} {}, sigAlg={}, reuse={})",
                signer.getCode(), signer.getId(), targetVslot, signer.getKeyLabel(), keyAlg, keySize, sigAlg, reuse);

        return new SignerCsrRequest.SignerCsrResponse(
                signer.getId(),
                signer.getCode(),
                targetVslot,
                signer.getKeyLabel(),
                keyAlg,
                keySize,
                sigAlg,
                subjectDn,
                csrRes.csrPem(),
                now
        );
    }

    /**
     * Retrieves the signer's generated CSR (or generates it on demand when {@code generateIfMissing=true}).
     */
    @Transactional
    public Optional<SignerCsrRequest.SignerCsrResponse> getCsr(Long id, boolean generateIfMissing) {
        OcspSignerEntity signer = requireSigner(id);
        if ((signer.getCsrPem() == null || signer.getCsrPem().isBlank()) && generateIfMissing) {
            return Optional.of(generateCsr(id, null));
        }
        if (signer.getCsrPem() == null || signer.getCsrPem().isBlank()) {
            return Optional.empty();
        }
        String primaryVslot = signer.getVslots().isEmpty()
                ? ocspSigner.getDefaultProviderId()
                : signer.getVslots().get(0).getDevice().getDeviceId();
        return Optional.of(new SignerCsrRequest.SignerCsrResponse(
                signer.getId(),
                signer.getCode(),
                primaryVslot,
                signer.getKeyLabel(),
                signer.getKeyAlgorithm(),
                signer.getKeySize(),
                signer.getSignatureAlgorithm(),
                signer.getSubjectDn(),
                signer.getCsrPem(),
                signer.getCsrGeneratedAt()
        ));
    }

    /**
     * Returns the signer's imported X.509 certificate if present.
     */
    @Transactional(readOnly = true)
    public Optional<SignerDto.SignerCertificateDto> getCertificate(Long id) {
        OcspSignerEntity signer = requireSigner(id);
        return Optional.ofNullable(buildCertDto(signer));
    }

    /**
     * Imports a CA-signed X.509 certificate into the signer and its bound HSM Vslot(s),
     * verifying key compatibility and live HSM mechanism support.
     */
    @Transactional
    public SignerDto importCertificate(Long id, SignerCertImportRequest request) {
        OcspSignerEntity signer = requireSigner(id);
        Map<String, ProviderDeviceInfo> liveDevices = mapLiveDevices();
        String primaryVslot = resolveTargetVslotForCsr(signer, null, liveDevices);

        String sigAlg = (request.signatureAlgorithm() != null && !request.signatureAlgorithm().isBlank())
                ? request.signatureAlgorithm().trim()
                : signer.getSignatureAlgorithm();
        boolean activateNow = request.activateImmediately() == null || Boolean.TRUE.equals(request.activateImmediately());

        // Remove previous unactivated/superseded signing_certificates row linked ONLY to this signer code if alias collides
        String certAlias = signer.getCode();
        if (signer.getSigningCertificateId() != null) {
            signingCertRepository.findById(signer.getSigningCertificateId()).ifPresent(existing -> {
                if (!existing.isActive()) {
                    signingCertRepository.delete(existing);
                    signingCertRepository.flush();
                }
            });
        }
        if (signingCertRepository.existsByAlias(certAlias)) {
            certAlias = signer.getCode() + "-" + (System.currentTimeMillis() % 100000);
        }

        SigningCertificateDto imported = signingCertificateService.addCertificate(new AddSigningCertificateRequest(
                certAlias,
                signer.getKeyLabel(),
                request.certificatePem().trim(),
                false,
                sigAlg,
                primaryVslot
        ));

        // Also import certificate object into any additional ACTIVE failover Vslots holding the same keyLabel
        X509CertificateHolder holder = SigningCertificateService.parsePem(request.certificatePem().trim());
        for (OcspSignerVslotEntity binding : signer.getVslots()) {
            String devId = binding.getDevice().getDeviceId();
            if (!devId.equals(primaryVslot)) {
                ProviderDeviceInfo info = liveDevices.get(devId);
                if (info != null && DeviceActivationState.ACTIVE.name().equals(info.activationState())
                        && info.keyLabels() != null && info.keyLabels().contains(signer.getKeyLabel())) {
                    try {
                        ocspSigner.importCertificateToToken(devId, signer.getKeyLabel(), holder);
                    } catch (Exception e) {
                        log.warn("Optional certificate import to failover Vslot '{}' skipped: {}", devId, e.getMessage());
                    }
                }
            }
        }

        signer.setSignatureAlgorithm(imported.signatureAlgorithm());
        signer.setCertificatePem(imported.certificatePem());
        signer.setCertSubjectDn(imported.subjectDn());
        signer.setCertIssuerDn(imported.issuerDn());
        signer.setCertSerialNumber(imported.serialNumber());
        signer.setCertNotBefore(imported.notBefore());
        signer.setCertNotAfter(imported.notAfter());
        signer.setSigningCertificateId(imported.id());
        signer.setStatus("CERT_IMPORTED");
        signerRepository.save(signer);

        if (activateNow) {
            return activateSigner(signer.getId());
        }
        return toDto(signer, mapLiveDevices());
    }

    @Transactional
    public SignerDto activateSigner(Long id) {
        OcspSignerEntity signer = requireSigner(id);
        if (signer.getSigningCertificateId() == null || signer.getCertificatePem() == null) {
            throw new IllegalStateException("Cannot activate signer '" + signer.getCode()
                    + "': import a CA-signed certificate first (POST /signers/" + id + "/cert)");
        }
        SigningCertificateDto activated = signingCertificateService.activate(signer.getSigningCertificateId());

        // Sync active flags across all signers whose underlying signing_certificates were auto-superseded
        for (OcspSignerEntity other : signerRepository.findAll()) {
            if (!other.getId().equals(signer.getId()) && other.getSigningCertificateId() != null) {
                boolean stillActive = signingCertRepository.findById(other.getSigningCertificateId())
                        .map(SigningCertificate::isActive)
                        .orElse(false);
                if (other.isActive() && !stillActive) {
                    other.setActive(false);
                    other.setStatus("INACTIVE");
                    signerRepository.save(other);
                }
            }
        }

        signer.setActive(true);
        signer.setActivatedAt(activated.activatedAt() != null ? activated.activatedAt() : Instant.now());
        signer.setStatus("ACTIVE");
        OcspSignerEntity saved = signerRepository.save(signer);
        return toDto(saved, mapLiveDevices());
    }

    @Transactional
    public SignerDto deactivateSigner(Long id) {
        OcspSignerEntity signer = requireSigner(id);
        if (!signer.isActive()) {
            return toDto(signer, mapLiveDevices());
        }
        if (signer.getSigningCertificateId() != null) {
            signingCertificateService.deactivate(signer.getSigningCertificateId());
        }
        signer.setActive(false);
        signer.setStatus("INACTIVE");
        OcspSignerEntity saved = signerRepository.save(signer);
        return toDto(saved, mapLiveDevices());
    }

    // ---- Internal helpers ----

    private OcspSignerEntity requireSigner(Long id) {
        return signerRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Signer not found: " + id));
    }

    private List<CryptoDeviceEntity> resolveVslotDevices(List<String> deviceIds) {
        if (deviceIds == null || deviceIds.isEmpty()) {
            throw new IllegalArgumentException("At least one HSM Vslot (deviceId) is required");
        }
        Set<String> uniqueIds = new LinkedHashSet<>();
        for (String raw : deviceIds) {
            if (raw != null && !raw.isBlank()) {
                uniqueIds.add(raw.trim());
            }
        }
        if (uniqueIds.isEmpty()) {
            throw new IllegalArgumentException("At least one non-blank HSM Vslot (deviceId) is required");
        }
        List<CryptoDeviceEntity> resolved = new ArrayList<>(uniqueIds.size());
        for (String devId : uniqueIds) {
            CryptoDeviceEntity dev = deviceRepository.findByDeviceId(devId)
                    .orElseThrow(() -> new IllegalArgumentException("HSM Vslot / device not found: '" + devId + "'"));
            resolved.add(dev);
        }
        return resolved;
    }

    private static void bindVslots(OcspSignerEntity signer, List<CryptoDeviceEntity> orderedDevices) {
        signer.getVslots().clear();
        for (int i = 0; i < orderedDevices.size(); i++) {
            signer.getVslots().add(OcspSignerVslotEntity.builder()
                    .signer(signer)
                    .device(orderedDevices.get(i))
                    .priorityOrder(i)
                    .role(i == 0 ? "PRIMARY" : "FAILOVER")
                    .build());
        }
    }

    private String resolveTargetVslotForCsr(
            OcspSignerEntity signer,
            String explicitVslot,
            Map<String, ProviderDeviceInfo> liveDevices) {
        if (explicitVslot != null && !explicitVslot.isBlank()) {
            String trimmed = explicitVslot.trim();
            boolean bound = signer.getVslots().stream()
                    .anyMatch(v -> trimmed.equals(v.getDevice().getDeviceId()));
            if (!bound) {
                throw new IllegalArgumentException("Vslot '" + trimmed + "' is not bound to signer '" + signer.getCode() + "'");
            }
            return trimmed;
        }
        // Prefer the first ACTIVE (unlocked) Vslot in priority order; otherwise return PRIMARY (index 0)
        for (OcspSignerVslotEntity binding : signer.getVslots()) {
            String devId = binding.getDevice().getDeviceId();
            ProviderDeviceInfo live = liveDevices.get(devId);
            if (live != null && DeviceActivationState.ACTIVE.name().equals(live.activationState())) {
                return devId;
            }
        }
        if (!signer.getVslots().isEmpty()) {
            return signer.getVslots().get(0).getDevice().getDeviceId();
        }
        return ocspSigner.getDefaultProviderId();
    }

    private Map<String, ProviderDeviceInfo> mapLiveDevices() {
        return ocspSigner.listProviders().stream()
                .collect(Collectors.toMap(ProviderDeviceInfo::providerId, Function.identity(), (a, b) -> a));
    }

    private SignerDto toDto(OcspSignerEntity entity, Map<String, ProviderDeviceInfo> liveDevices) {
        List<SignerDto.SignerVslotDto> vslotDtos = new ArrayList<>();
        if (entity.getVslots() != null) {
            for (OcspSignerVslotEntity v : entity.getVslots()) {
                CryptoDeviceEntity dev = v.getDevice();
                CryptoProviderEntity prov = dev.getProvider();
                ProviderDeviceInfo live = liveDevices.get(dev.getDeviceId());
                String state = live != null ? live.activationState() : DeviceActivationState.LOCKED.name();
                boolean healthy = live != null && live.healthy();
                boolean keyPresent = live != null && live.keyLabels() != null
                        && live.keyLabels().contains(entity.getKeyLabel());
                Long resolvedSlotId = dev.getSlotId() != null
                        ? dev.getSlotId()
                        : (live != null && healthy ? live.slotId() : null);
                String resolvedToken = (dev.getTokenLabel() != null && !dev.getTokenLabel().isBlank())
                        ? dev.getTokenLabel()
                        : (live != null ? live.tokenLabel() : null);

                vslotDtos.add(new SignerDto.SignerVslotDto(
                        dev.getId(),
                        dev.getDeviceId(),
                        prov.getId(),
                        prov.getCode(),
                        prov.getName(),
                        prov.getWrapperType(),
                        prov.getLibraryPath(),
                        prov.getLibraryWrapperPath(),
                        resolvedToken,
                        resolvedSlotId,
                        dev.getSlotListIndex(),
                        v.getPriorityOrder(),
                        v.getRole(),
                        state,
                        healthy,
                        keyPresent
                ));
            }
        }

        SignerDto.SignerCertificateDto certDto = buildCertDto(entity);
        boolean hasCsr = entity.getCsrPem() != null && !entity.getCsrPem().isBlank();
        boolean hasCert = certDto != null;
        String effectiveStatus = entity.getStatus();
        if (certDto != null && certDto.expired()) {
            effectiveStatus = "EXPIRED";
        } else if (entity.isActive()) {
            effectiveStatus = "ACTIVE";
        }

        return new SignerDto(
                entity.getId(),
                entity.getCode(),
                entity.getName(),
                effectiveStatus,
                entity.getSubjectDn(),
                entity.getKeyLabel(),
                entity.getKeyAlgorithm(),
                entity.getKeySize(),
                entity.getSignatureAlgorithm(),
                List.copyOf(vslotDtos),
                hasCsr,
                entity.getCsrPem(),
                entity.getCsrGeneratedAt(),
                hasCert,
                certDto,
                entity.isActive(),
                entity.getActivatedAt(),
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }

    private SignerDto.SignerCertificateDto buildCertDto(OcspSignerEntity entity) {
        if (entity.getCertificatePem() == null || entity.getCertificatePem().isBlank()) {
            return null;
        }
        Instant now = Instant.now();
        Instant notAfter = entity.getCertNotAfter();
        long daysLeft = notAfter != null ? ChronoUnit.DAYS.between(now, notAfter) : -1;
        boolean expired = notAfter != null && now.isAfter(notAfter);
        return new SignerDto.SignerCertificateDto(
                entity.getSigningCertificateId(),
                entity.getCertSubjectDn(),
                entity.getCertIssuerDn(),
                entity.getCertSerialNumber(),
                entity.getCertNotBefore(),
                notAfter,
                daysLeft,
                expired,
                entity.getSignatureAlgorithm(),
                entity.getCertificatePem()
        );
    }

    private static String normalizeKeyAlg(String raw) {
        String clean = requireClean(raw, "keyAlgorithm").toUpperCase();
        if ("ECDSA".equals(clean)) {
            return "EC";
        }
        if (!"RSA".equals(clean) && !"EC".equals(clean)) {
            throw new IllegalArgumentException("Unsupported keyAlgorithm '" + raw + "'. Supported: [RSA, EC]");
        }
        return clean;
    }

    private static int resolveKeySize(String keyAlg, Integer requestedSize) {
        if (requestedSize == null) {
            return "EC".equals(keyAlg) ? 256 : 3072;
        }
        List<Integer> allowed = "EC".equals(keyAlg) ? List.of(256, 384, 521) : List.of(2048, 3072, 4096);
        if (!allowed.contains(requestedSize)) {
            throw new IllegalArgumentException("Unsupported " + keyAlg + " key size: " + requestedSize
                    + " bits. Allowed: " + allowed);
        }
        return requestedSize;
    }

    private static String validateSignatureAlgForKeyType(String sigAlg, String keyAlg) {
        String clean = requireClean(sigAlg, "signatureAlgorithm");
        if (!SigningAlgorithm.isSupportedForKeyType(clean, keyAlg)) {
            throw new IllegalArgumentException("Signature algorithm '" + clean
                    + "' is incompatible with key algorithm " + keyAlg
                    + ". Allowed: " + SigningAlgorithm.namesForKeyType(keyAlg));
        }
        return clean;
    }

    private static String requireClean(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value.trim();
    }
}

