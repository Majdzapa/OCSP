package lu.incert.ocsp.signing.service;

import lu.incert.ocsp.signing.dto.AddSigningCertificateRequest;
import lu.incert.ocsp.signing.dto.GenerateCsrRequest;
import lu.incert.ocsp.signing.dto.GenerateCsrResponse;
import lu.incert.ocsp.signing.dto.OcspKeyDto;
import lu.incert.ocsp.signing.dto.SignerCertImportRequest;
import lu.incert.ocsp.signing.dto.SignerCsrRequest;
import lu.incert.ocsp.signing.dto.SignerDto;
import lu.incert.ocsp.signing.dto.SignerRequest;
import lu.incert.ocsp.signing.dto.SigningCertificateDto;
import lu.incert.ocsp.signing.entity.CryptoDeviceEntity;
import lu.incert.ocsp.signing.entity.CryptoProviderEntity;
import lu.incert.ocsp.signing.entity.OcspKeyEntity;
import lu.incert.ocsp.signing.entity.OcspSignerEntity;
import lu.incert.ocsp.signing.entity.OcspSignerTokenEntity;
import lu.incert.ocsp.signing.entity.SigningCertificate;
import lu.incert.ocsp.signing.hsm.OcspSigner;
import lu.incert.ocsp.signing.hsm.SigningAlgorithm;
import lu.incert.ocsp.signing.port.DeviceActivationState;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import lu.incert.ocsp.signing.repository.CryptoDeviceRepository;
import lu.incert.ocsp.signing.repository.OcspKeyRepository;
import lu.incert.ocsp.signing.repository.OcspSignerRepository;
import lu.incert.ocsp.signing.repository.SigningCertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Manages first-class OCSP {@code Signer} aggregates ({@code ocsp_signers}), their persisted
 * cryptographic keys ({@code ocsp_keys}), and their ordered PKCS#11 HSM Tokens ({@code ocsp_signer_tokens}).
 * <p>
 * Minimal Token Touch Policy: the hardware PKCS#11 token is ONLY touched during keypair/CSR generation
 * ({@code POST /signers/{id}/csr}) and live OCSP response signing ({@code POST /ocsp}). All UI reads,
 * health checks, and X.509 certificate imports execute against {@code ocsp_keys} in MariaDB with zero
 * PKCS#11 object scans or NVRAM writes.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OcspSignerManagementService {

    private final OcspSignerRepository signerRepository;
    private final OcspKeyRepository keyRepository;
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
    public List<OcspKeyDto> listKeys() {
        return keyRepository.findAllByOrderByIdDesc().stream()
                .map(OcspSignerManagementService::toKeyDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public SignerDto getById(Long id) {
        OcspSignerEntity entity = requireSigner(id);
        return toDto(entity, mapLiveDevices());
    }

    @Transactional
    public SignerDto createSigner(SignerRequest request) {
        String cleanCode = resolveOrGenerateUuid(request.code());
        if (signerRepository.existsByCode(cleanCode)) {
            throw new IllegalArgumentException("Signer with code '" + cleanCode + "' already exists");
        }

        List<CryptoDeviceEntity> orderedTokens = resolveTokenDevices(request.tokenDeviceIds());

        OcspKeyEntity linkedKey = null;
        String cleanKeyLabel;
        String keyAlg;
        int keySize;

        if (request.keyId() != null) {
            linkedKey = keyRepository.findById(request.keyId())
                    .orElseThrow(() -> new IllegalArgumentException("Key not found: " + request.keyId()));
            cleanKeyLabel = linkedKey.getKeyLabel();
            keyAlg = linkedKey.getKeyAlgorithm();
            keySize = linkedKey.getKeySize();
        } else {
            cleanKeyLabel = resolveOrGenerateUuid(request.keyLabel());
            linkedKey = keyRepository.findByKeyLabel(cleanKeyLabel).orElse(null);
            if (linkedKey != null) {
                keyAlg = linkedKey.getKeyAlgorithm();
                keySize = linkedKey.getKeySize();
            } else {
                keyAlg = normalizeKeyAlg(request.keyAlgorithm() != null ? request.keyAlgorithm() : "RSA");
                keySize = resolveKeySize(keyAlg, request.keySize());
            }
        }

        String sigAlg = validateSignatureAlgForKeyType(request.signatureAlgorithm(), keyAlg);

        OcspSignerEntity signer = OcspSignerEntity.builder()
                .code(cleanCode)
                .name(requireClean(request.name(), "name"))
                .status("DRAFT")
                .subjectDn(requireClean(request.subjectDn(), "subjectDn"))
                .key(linkedKey)
                .keyLabel(cleanKeyLabel)
                .keyAlgorithm(keyAlg)
                .keySize(keySize)
                .signatureAlgorithm(sigAlg)
                .active(false)
                .build();

        bindTokens(signer, orderedTokens);
        OcspSignerEntity saved = signerRepository.save(signer);
        log.info("Created OCSP Signer '{}' (id={}, keyId={}, keyLabel='{}', key={} {}, sigAlg={}, tokens={})",
                saved.getCode(), saved.getId(),
                saved.getKey() != null ? saved.getKey().getId() : null,
                saved.getKeyLabel(), saved.getKeyAlgorithm(),
                saved.getKeySize(), saved.getSignatureAlgorithm(),
                orderedTokens.stream().map(CryptoDeviceEntity::getDeviceId).toList());
        return toDto(saved, mapLiveDevices());
    }

    @Transactional
    public SignerDto updateSigner(Long id, SignerRequest request) {
        OcspSignerEntity signer = requireSigner(id);
        String cleanCode = (request.code() != null && !request.code().isBlank())
                ? request.code().trim()
                : signer.getCode();
        signerRepository.findByCode(cleanCode).ifPresent(existing -> {
            if (!existing.getId().equals(id)) {
                throw new IllegalArgumentException("Another signer already uses code '" + cleanCode + "'");
            }
        });

        List<CryptoDeviceEntity> orderedTokens = resolveTokenDevices(request.tokenDeviceIds());

        OcspKeyEntity linkedKey = signer.getKey();
        String cleanKeyLabel;
        String keyAlg;
        int keySize;

        if (request.keyId() != null) {
            linkedKey = keyRepository.findById(request.keyId())
                    .orElseThrow(() -> new IllegalArgumentException("Key not found: " + request.keyId()));
            cleanKeyLabel = linkedKey.getKeyLabel();
            keyAlg = linkedKey.getKeyAlgorithm();
            keySize = linkedKey.getKeySize();
        } else {
            cleanKeyLabel = (request.keyLabel() != null && !request.keyLabel().isBlank())
                    ? request.keyLabel().trim()
                    : signer.getKeyLabel();
            if (linkedKey != null && !linkedKey.getKeyLabel().equals(cleanKeyLabel)) {
                linkedKey = keyRepository.findByKeyLabel(cleanKeyLabel).orElse(null);
            }
            if (linkedKey != null) {
                keyAlg = linkedKey.getKeyAlgorithm();
                keySize = linkedKey.getKeySize();
            } else {
                keyAlg = normalizeKeyAlg(request.keyAlgorithm() != null ? request.keyAlgorithm() : signer.getKeyAlgorithm());
                keySize = resolveKeySize(keyAlg, request.keySize() != null ? request.keySize() : signer.getKeySize());
            }
        }

        String sigAlg = validateSignatureAlgForKeyType(request.signatureAlgorithm(), keyAlg);

        signer.setCode(cleanCode);
        signer.setName(requireClean(request.name(), "name"));
        signer.setSubjectDn(requireClean(request.subjectDn(), "subjectDn"));
        signer.setKey(linkedKey);
        signer.setKeyLabel(cleanKeyLabel);
        signer.setKeyAlgorithm(keyAlg);
        signer.setKeySize(keySize);
        signer.setSignatureAlgorithm(sigAlg);
        bindTokens(signer, orderedTokens);

        OcspSignerEntity saved = signerRepository.save(signer);
        if (saved.getSigningCertificateId() != null) {
            signingCertRepository.findById(saved.getSigningCertificateId()).ifPresent(sc -> {
                sc.setProviderId(orderedTokens.get(0).getDeviceId());
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
     * Touches the unlocked PKCS#11 HSM Token to generate a non-extractable keypair (or reuse a linked key),
     * persists the extracted {@link SubjectPublicKeyInfo} once into {@code ocsp_keys}, signs a PKCS#10 CSR,
     * and stores {@code csrPem} on the Signer.
     */
    @Transactional
    public SignerCsrRequest.SignerCsrResponse generateCsr(Long id, SignerCsrRequest request) {
        OcspSignerEntity signer = requireSigner(id);
        Map<String, ProviderDeviceInfo> liveDevices = mapLiveDevices();

        CryptoDeviceEntity targetTokenEntity = resolveTargetTokenEntityForCsr(
                signer, request != null ? request.tokenDeviceId() : null, liveDevices);
        String targetTokenId = targetTokenEntity != null
                ? targetTokenEntity.getDeviceId()
                : ocspSigner.getDefaultProviderId();

        OcspKeyEntity existingKey = signer.getKey() != null
                ? signer.getKey()
                : keyRepository.findByKeyLabel(signer.getKeyLabel()).orElse(null);

        String subjectDn = (request != null && request.subjectDn() != null && !request.subjectDn().isBlank())
                ? request.subjectDn().trim()
                : signer.getSubjectDn();
        String keyAlg = existingKey != null
                ? existingKey.getKeyAlgorithm()
                : ((request != null && request.keyAlgorithm() != null && !request.keyAlgorithm().isBlank())
                        ? normalizeKeyAlg(request.keyAlgorithm())
                        : signer.getKeyAlgorithm());
        int keySize = existingKey != null
                ? existingKey.getKeySize()
                : ((request != null && request.keySize() != null)
                        ? resolveKeySize(keyAlg, request.keySize())
                        : signer.getKeySize());
        String sigAlg = (request != null && request.signatureAlgorithm() != null && !request.signatureAlgorithm().isBlank())
                ? validateSignatureAlgForKeyType(request.signatureAlgorithm(), keyAlg)
                : signer.getSignatureAlgorithm();

        boolean reuse = (request != null && request.reuseExistingKey() != null)
                ? request.reuseExistingKey()
                : (existingKey != null);

        GenerateCsrResponse csrRes = signingCertificateService.generateCsr(new GenerateCsrRequest(
                signer.getKeyLabel(),
                subjectDn,
                keyAlg,
                keySize,
                reuse,
                targetTokenId,
                sigAlg
        ));

        Instant now = Instant.now();
        OcspKeyEntity persistedKey = existingKey;
        if (persistedKey == null) {
            SubjectPublicKeyInfo spki = SigningCertificateService.extractPublicKeyFromCsrPem(csrRes.csrPem());
            if (spki != null) {
                persistedKey = keyRepository.save(OcspKeyEntity.builder()
                        .keyLabel(signer.getKeyLabel())
                        .ckaIdHex(HexFormat.of().formatHex(signer.getKeyLabel().getBytes(StandardCharsets.UTF_8)))
                        .tokenDevice(targetTokenEntity)
                        .keyAlgorithm(keyAlg)
                        .keySize(keySize)
                        .publicKeyPem(SigningCertificateService.toPublicKeyPem(spki))
                        .publicKeySha1(SigningCertificateService.computePublicKeySha1Hex(spki))
                        .generatedAt(now)
                        .build());
            }
        }

        signer.setKey(persistedKey);
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

        log.info("Generated CSR for Signer '{}' (id={}) on Token '{}' (keyId={}, keyLabel='{}', key={} {}, sigAlg={}, reuse={})",
                signer.getCode(), signer.getId(), targetTokenId,
                persistedKey != null ? persistedKey.getId() : null,
                signer.getKeyLabel(), keyAlg, keySize, sigAlg, reuse);

        return new SignerCsrRequest.SignerCsrResponse(
                signer.getId(),
                signer.getCode(),
                targetTokenId,
                persistedKey != null ? persistedKey.getId() : null,
                signer.getKeyLabel(),
                keyAlg,
                keySize,
                persistedKey != null ? persistedKey.getPublicKeySha1() : null,
                sigAlg,
                subjectDn,
                csrRes.csrPem(),
                now
        );
    }

    /**
     * Retrieves the signer's generated CSR from MariaDB (zero HSM calls unless {@code generateIfMissing=true}).
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
        String primaryToken = signer.getTokens().isEmpty()
                ? ocspSigner.getDefaultProviderId()
                : signer.getTokens().get(0).getTokenDevice().getDeviceId();
        OcspKeyEntity key = signer.getKey();
        return Optional.of(new SignerCsrRequest.SignerCsrResponse(
                signer.getId(),
                signer.getCode(),
                primaryToken,
                key != null ? key.getId() : null,
                signer.getKeyLabel(),
                signer.getKeyAlgorithm(),
                signer.getKeySize(),
                key != null ? key.getPublicKeySha1() : null,
                signer.getSignatureAlgorithm(),
                signer.getSubjectDn(),
                signer.getCsrPem(),
                signer.getCsrGeneratedAt()
        ));
    }

    /**
     * Returns the signer's imported X.509 certificate from MariaDB (zero HSM calls).
     */
    @Transactional(readOnly = true)
    public Optional<SignerDto.SignerCertificateDto> getCertificate(Long id) {
        OcspSignerEntity signer = requireSigner(id);
        return Optional.ofNullable(buildCertDto(signer));
    }

    /**
     * Imports a CA-signed X.509 certificate into the Signer with ZERO PKCS#11 token calls:
     * public-key ownership is verified directly against {@code ocsp_keys.public_key_pem} in MariaDB,
     * avoiding HSM NVRAM {@code CKO_CERTIFICATE} clutter and working even while tokens are {@code LOCKED}.
     */
    @Transactional
    public SignerDto importCertificate(Long id, SignerCertImportRequest request) {
        OcspSignerEntity signer = requireSigner(id);
        Map<String, ProviderDeviceInfo> liveDevices = mapLiveDevices();
        CryptoDeviceEntity primaryTokenEntity = resolveTargetTokenEntityForCsr(signer, null, liveDevices);
        String primaryTokenId = primaryTokenEntity != null
                ? primaryTokenEntity.getDeviceId()
                : ocspSigner.getDefaultProviderId();

        String sigAlg = (request.signatureAlgorithm() != null && !request.signatureAlgorithm().isBlank())
                ? request.signatureAlgorithm().trim()
                : signer.getSignatureAlgorithm();
        boolean activateNow = request.activateImmediately() == null || Boolean.TRUE.equals(request.activateImmediately());

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
                primaryTokenId,
                signer.getId()
        ));

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

    private List<CryptoDeviceEntity> resolveTokenDevices(List<String> deviceIds) {
        if (deviceIds == null || deviceIds.isEmpty()) {
            throw new IllegalArgumentException("At least one HSM Token (deviceId) is required");
        }
        Set<String> uniqueIds = new LinkedHashSet<>();
        for (String raw : deviceIds) {
            if (raw != null && !raw.isBlank()) {
                uniqueIds.add(raw.trim());
            }
        }
        if (uniqueIds.isEmpty()) {
            throw new IllegalArgumentException("At least one non-blank HSM Token (deviceId) is required");
        }
        List<CryptoDeviceEntity> resolved = new ArrayList<>(uniqueIds.size());
        for (String devId : uniqueIds) {
            CryptoDeviceEntity dev = deviceRepository.findByDeviceId(devId)
                    .orElseThrow(() -> new IllegalArgumentException("HSM Token / device not found: '" + devId + "'"));
            resolved.add(dev);
        }
        return resolved;
    }

    private static void bindTokens(OcspSignerEntity signer, List<CryptoDeviceEntity> orderedTokens) {
        signer.getTokens().clear();
        for (int i = 0; i < orderedTokens.size(); i++) {
            signer.getTokens().add(OcspSignerTokenEntity.builder()
                    .signer(signer)
                    .tokenDevice(orderedTokens.get(i))
                    .priorityOrder(i)
                    .role(i == 0 ? "PRIMARY" : "FAILOVER")
                    .build());
        }
    }

    private CryptoDeviceEntity resolveTargetTokenEntityForCsr(
            OcspSignerEntity signer,
            String explicitTokenDeviceId,
            Map<String, ProviderDeviceInfo> liveDevices) {
        if (explicitTokenDeviceId != null && !explicitTokenDeviceId.isBlank()) {
            String trimmed = explicitTokenDeviceId.trim();
            return signer.getTokens().stream()
                    .map(OcspSignerTokenEntity::getTokenDevice)
                    .filter(d -> trimmed.equals(d.getDeviceId()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Token '" + trimmed + "' is not bound to signer '" + signer.getCode() + "'"));
        }
        for (OcspSignerTokenEntity binding : signer.getTokens()) {
            CryptoDeviceEntity dev = binding.getTokenDevice();
            ProviderDeviceInfo live = liveDevices.get(dev.getDeviceId());
            if (live != null && DeviceActivationState.ACTIVE.name().equals(live.activationState())) {
                return dev;
            }
        }
        if (!signer.getTokens().isEmpty()) {
            return signer.getTokens().get(0).getTokenDevice();
        }
        return null;
    }

    private Map<String, ProviderDeviceInfo> mapLiveDevices() {
        return ocspSigner.listProviders().stream()
                .collect(Collectors.toMap(ProviderDeviceInfo::providerId, Function.identity(), (a, b) -> a));
    }

    private SignerDto toDto(OcspSignerEntity entity, Map<String, ProviderDeviceInfo> liveDevices) {
        OcspKeyEntity keyEntity = entity.getKey();
        OcspKeyDto keyDto = keyEntity != null ? toKeyDto(keyEntity) : null;

        List<SignerDto.SignerTokenDto> tokenDtos = new ArrayList<>();
        if (entity.getTokens() != null) {
            for (OcspSignerTokenEntity t : entity.getTokens()) {
                CryptoDeviceEntity dev = t.getTokenDevice();
                CryptoProviderEntity prov = dev.getProvider();
                ProviderDeviceInfo live = liveDevices.get(dev.getDeviceId());
                String state = live != null ? live.activationState() : DeviceActivationState.LOCKED.name();
                boolean healthy = live != null && live.healthy();
                boolean keyRegistered = keyEntity != null
                        && (keyEntity.getTokenDevice() == null
                                || keyEntity.getTokenDevice().getId() == null
                                || keyEntity.getTokenDevice().getId().equals(dev.getId()));
                Long resolvedSlotId = dev.getSlotId() != null
                        ? dev.getSlotId()
                        : (live != null && healthy ? live.slotId() : null);
                String resolvedToken = (dev.getTokenLabel() != null && !dev.getTokenLabel().isBlank())
                        ? dev.getTokenLabel()
                        : (live != null ? live.tokenLabel() : null);

                tokenDtos.add(new SignerDto.SignerTokenDto(
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
                        t.getPriorityOrder(),
                        t.getRole(),
                        state,
                        healthy,
                        keyRegistered
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
                keyEntity != null ? keyEntity.getId() : null,
                keyDto,
                entity.getKeyLabel(),
                entity.getKeyAlgorithm(),
                entity.getKeySize(),
                entity.getSignatureAlgorithm(),
                List.copyOf(tokenDtos),
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

    private static OcspKeyDto toKeyDto(OcspKeyEntity entity) {
        CryptoDeviceEntity td = entity.getTokenDevice();
        return new OcspKeyDto(
                entity.getId(),
                entity.getKeyLabel(),
                entity.getCkaIdHex(),
                td != null ? td.getId() : null,
                td != null ? td.getDeviceId() : null,
                td != null ? td.getTokenLabel() : null,
                entity.getKeyAlgorithm(),
                entity.getKeySize(),
                entity.getPublicKeyPem(),
                entity.getPublicKeySha1(),
                entity.getGeneratedAt(),
                entity.getCreatedAt()
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

    private static String resolveOrGenerateUuid(String raw) {
        if (raw == null || raw.isBlank()) {
            return UUID.randomUUID().toString();
        }
        return raw.trim();
    }

    private static String requireClean(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
        return value.trim();
    }
}
