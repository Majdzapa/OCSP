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
        Map<String, ProviderDeviceInfo> liveDevices = mapLiveDevices();
        List<OcspSignerEntity> allSigners = signerRepository.findAllByOrderByIdAsc();
        Map<Long, OcspSignerEntity> signerByKeyId = new java.util.HashMap<>();
        Map<String, OcspSignerEntity> signerByKeyLabel = new java.util.HashMap<>();
        for (OcspSignerEntity s : allSigners) {
            if (s.getKey() != null && s.getKey().getId() != null) {
                signerByKeyId.merge(s.getKey().getId(), s, (a, b) -> b.isActive() ? b : a);
            }
            if (s.getKeyLabel() != null && !s.getKeyLabel().isBlank()) {
                signerByKeyLabel.merge(s.getKeyLabel(), s, (a, b) -> b.isActive() ? b : a);
            }
        }
        return keyRepository.findAllByOrderByIdDesc().stream()
                .map(k -> {
                    OcspSignerEntity bound = signerByKeyId.get(k.getId());
                    if (bound == null && k.getKeyLabel() != null) {
                        bound = signerByKeyLabel.get(k.getKeyLabel());
                    }
                    return toKeyDto(k, liveDevices, bound);
                })
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

        boolean alreadyHasCsr = signer.getCsrPem() != null && !signer.getCsrPem().isBlank();
        OcspKeyEntity existingKey = signer.getKey() != null
                ? signer.getKey()
                : keyRepository.findByKeyLabel(signer.getKeyLabel()).orElse(null);

        // Reuse ONLY when explicitly requested (reuseExistingKey=true) OR on the very first CSR generation
        // of a DRAFT signer that was explicitly bound to an existing OcspKeyEntity (signer.getKey() != null).
        // Re-generating CSR ALWAYS defaults to reuse=false and generates a brand-new UUID keypair on the token.
        boolean reuse = (request != null && request.reuseExistingKey() != null)
                ? request.reuseExistingKey()
                : (!alreadyHasCsr && signer.getKey() != null);

        String targetKeyLabel;
        if (reuse) {
            targetKeyLabel = existingKey != null ? existingKey.getKeyLabel() : signer.getKeyLabel();
        } else if (alreadyHasCsr || existingKey != null) {
            targetKeyLabel = UUID.randomUUID().toString();
        } else {
            targetKeyLabel = signer.getKeyLabel();
        }

        String subjectDn = (request != null && request.subjectDn() != null && !request.subjectDn().isBlank())
                ? request.subjectDn().trim()
                : signer.getSubjectDn();
        String keyAlg = (reuse && existingKey != null)
                ? existingKey.getKeyAlgorithm()
                : ((request != null && request.keyAlgorithm() != null && !request.keyAlgorithm().isBlank())
                        ? normalizeKeyAlg(request.keyAlgorithm())
                        : signer.getKeyAlgorithm());
        int keySize = (reuse && existingKey != null)
                ? existingKey.getKeySize()
                : ((request != null && request.keySize() != null)
                        ? resolveKeySize(keyAlg, request.keySize())
                        : signer.getKeySize());
        String sigAlg = (request != null && request.signatureAlgorithm() != null && !request.signatureAlgorithm().isBlank())
                ? validateSignatureAlgForKeyType(request.signatureAlgorithm(), keyAlg)
                : signer.getSignatureAlgorithm();

        GenerateCsrResponse csrRes = signingCertificateService.generateCsr(new GenerateCsrRequest(
                targetKeyLabel,
                subjectDn,
                keyAlg,
                keySize,
                reuse,
                targetTokenId,
                sigAlg
        ));

        Instant now = Instant.now();
        OcspKeyEntity persistedKey = reuse ? existingKey : null;
        if (persistedKey == null) {
            SubjectPublicKeyInfo spki = SigningCertificateService.extractPublicKeyFromCsrPem(csrRes.csrPem());
            if (spki != null) {
                persistedKey = keyRepository.save(OcspKeyEntity.builder()
                        .keyLabel(targetKeyLabel)
                        .ckaIdHex(HexFormat.of().formatHex(targetKeyLabel.getBytes(StandardCharsets.UTF_8)))
                        .tokenDevice(targetTokenEntity)
                        .signer(signer)
                        .keyAlgorithm(keyAlg)
                        .keySize(keySize)
                        .publicKeyPem(SigningCertificateService.toPublicKeyPem(spki))
                        .publicKeySha1(SigningCertificateService.computePublicKeySha1Hex(spki))
                        .csrPem(csrRes.csrPem())
                        .csrGeneratedAt(now)
                        .active(false)
                        .generatedAt(now)
                        .build());
            }
        } else {
            persistedKey.setSigner(signer);
            persistedKey.setCsrPem(csrRes.csrPem());
            persistedKey.setCsrGeneratedAt(now);
            persistedKey = keyRepository.save(persistedKey);
        }

        // EJBCA Zero-Downtime Key Rollover:
        // If the signer is ALREADY ACTIVE and we generated a new keypair (!reuse), keep the currently
        // active key & certificate untouched on the signer while staging the new key as CSR_PENDING!
        if (signer.isActive() && !reuse) {
            log.info("Staged next keypair & CSR for ACTIVE Signer '{}' (id={}) on Token '{}' (nextKeyId={}, keyLabel='{}') without disrupting active signing",
                    signer.getCode(), signer.getId(), targetTokenId,
                    persistedKey != null ? persistedKey.getId() : null, targetKeyLabel);
            return new SignerCsrRequest.SignerCsrResponse(
                    signer.getId(),
                    signer.getCode(),
                    targetTokenId,
                    persistedKey != null ? persistedKey.getId() : null,
                    targetKeyLabel,
                    keyAlg,
                    keySize,
                    persistedKey != null ? persistedKey.getPublicKeySha1() : null,
                    sigAlg,
                    subjectDn,
                    csrRes.csrPem(),
                    now
            );
        }

        // Inactive signer: point the signer to the newly generated key/CSR
        signer.setKey(persistedKey);
        signer.setKeyLabel(targetKeyLabel);
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

        if (signer.getKey() != null) {
            OcspKeyEntity k = signer.getKey();
            k.setSigner(signer);
            k.setCertificatePem(imported.certificatePem());
            k.setCertSubjectDn(imported.subjectDn());
            k.setCertIssuerDn(imported.issuerDn());
            k.setCertSerialNumber(imported.serialNumber());
            k.setCertNotBefore(imported.notBefore());
            k.setCertNotAfter(imported.notAfter());
            k.setSigningCertificateId(imported.id());
            keyRepository.save(k);
        }

        if (activateNow) {
            return activateSigner(signer.getId());
        }
        return toDto(signer, mapLiveDevices());
    }

    /**
     * Imports a CA-signed X.509 certificate onto a specific key owned by the Signer (EJBCA zero-downtime
     * rollover). Zero PKCS#11 calls — public-key ownership is verified directly against {@code ocsp_keys}.
     * If the signer is already active on another key, that active key stays live until {@link #activateKey} is called.
     */
    @Transactional
    public SignerDto importCertificateForKey(Long signerId, Long keyId, SignerCertImportRequest request) {
        OcspSignerEntity signer = requireSigner(signerId);
        OcspKeyEntity key = keyRepository.findById(keyId)
                .orElseThrow(() -> new IllegalArgumentException("Key not found: " + keyId));
        if (key.getSigner() != null && !key.getSigner().getId().equals(signerId)) {
            throw new IllegalArgumentException("Key #" + keyId + " belongs to a different signer");
        }
        key.setSigner(signer);

        Map<String, ProviderDeviceInfo> liveDevices = mapLiveDevices();
        String tokenDeviceId = key.getTokenDevice() != null
                ? key.getTokenDevice().getDeviceId()
                : (signer.getTokens().isEmpty()
                        ? ocspSigner.getDefaultProviderId()
                        : signer.getTokens().get(0).getTokenDevice().getDeviceId());

        String sigAlg = (request.signatureAlgorithm() != null && !request.signatureAlgorithm().isBlank())
                ? request.signatureAlgorithm().trim()
                : signer.getSignatureAlgorithm();
        boolean activateNow = Boolean.TRUE.equals(request.activateImmediately());

        if (key.getSigningCertificateId() != null) {
            signingCertRepository.findById(key.getSigningCertificateId()).ifPresent(existing -> {
                if (!existing.isActive()) {
                    signingCertRepository.delete(existing);
                    signingCertRepository.flush();
                }
            });
        }

        String certAlias = signer.getCode() + "-k" + key.getId();
        if (signingCertRepository.existsByAlias(certAlias)) {
            certAlias = certAlias + "-" + (System.currentTimeMillis() % 100000);
        }

        // Verify & register SigningCertificate without overwriting an already-active signer's live cert
        boolean mirrorToSignerNow = !signer.isActive() || (signer.getKey() != null && signer.getKey().getId().equals(key.getId()));
        SigningCertificateDto imported = signingCertificateService.addCertificate(new AddSigningCertificateRequest(
                certAlias,
                key.getKeyLabel(),
                request.certificatePem().trim(),
                false,
                sigAlg,
                tokenDeviceId,
                mirrorToSignerNow ? signer.getId() : null
        ));

        key.setCertificatePem(imported.certificatePem());
        key.setCertSubjectDn(imported.subjectDn());
        key.setCertIssuerDn(imported.issuerDn());
        key.setCertSerialNumber(imported.serialNumber());
        key.setCertNotBefore(imported.notBefore());
        key.setCertNotAfter(imported.notAfter());
        key.setSigningCertificateId(imported.id());
        keyRepository.save(key);

        if (mirrorToSignerNow) {
            signer.setKey(key);
            signer.setKeyLabel(key.getKeyLabel());
            signer.setSignatureAlgorithm(imported.signatureAlgorithm());
            signer.setCertificatePem(imported.certificatePem());
            signer.setCertSubjectDn(imported.subjectDn());
            signer.setCertIssuerDn(imported.issuerDn());
            signer.setCertSerialNumber(imported.serialNumber());
            signer.setCertNotBefore(imported.notBefore());
            signer.setCertNotAfter(imported.notAfter());
            signer.setSigningCertificateId(imported.id());
            if (!signer.isActive()) {
                signer.setStatus("CERT_IMPORTED");
            }
            signerRepository.save(signer);
        }

        if (activateNow) {
            return activateKey(signerId, keyId);
        }
        return toDto(signer, liveDevices);
    }

    /**
     * Atomically activates a specific key under the Signer (EJBCA zero-downtime key switch):
     * enforces at most ONE active key per Signer AND at most ONE active key per HSM Token,
     * and refuses activation if the key's HSM Token is deactivated/LOCKED.
     */
    @Transactional
    public SignerDto activateKey(Long signerId, Long keyId) {
        OcspSignerEntity signer = requireSigner(signerId);
        OcspKeyEntity key = keyRepository.findById(keyId)
                .orElseThrow(() -> new IllegalArgumentException("Key not found: " + keyId));
        if (key.getSigner() != null && !key.getSigner().getId().equals(signerId)) {
            throw new IllegalArgumentException("Key #" + keyId + " does not belong to signer " + signerId);
        }
        if (key.getSigningCertificateId() == null || key.getCertificatePem() == null || key.getCertificatePem().isBlank()) {
            throw new IllegalStateException("Cannot activate key '" + key.getKeyLabel()
                    + "': import a CA-signed X.509 certificate for this key first.");
        }

        Map<String, ProviderDeviceInfo> liveDevices = mapLiveDevices();
        if (!liveDevices.isEmpty()) {
            boolean tokenActive;
            if (key.getTokenDevice() != null) {
                ProviderDeviceInfo info = liveDevices.get(key.getTokenDevice().getDeviceId());
                tokenActive = info != null && DeviceActivationState.ACTIVE.name().equals(info.activationState());
            } else {
                tokenActive = signer.getTokens().stream().anyMatch(t -> {
                    ProviderDeviceInfo info = liveDevices.get(t.getTokenDevice().getDeviceId());
                    return info != null && DeviceActivationState.ACTIVE.name().equals(info.activationState());
                });
            }
            if (!tokenActive) {
                String tokName = key.getTokenDevice() != null ? key.getTokenDevice().getDeviceId() : "bound token";
                throw new IllegalStateException("Cannot activate key '" + key.getKeyLabel()
                        + "': HSM token '" + tokName + "' is deactivated/LOCKED. Activate the token first.");
            }
        }

        SigningCertificateDto activated = signingCertificateService.activate(key.getSigningCertificateId());
        Instant activatedAt = activated.activatedAt() != null ? activated.activatedAt() : Instant.now();

        // 1. Deactivate all other keys under the SAME Signer (max 1 active key per Signer)
        for (OcspKeyEntity sibling : keyRepository.findAllBySigner_IdOrderByIdDesc(signerId)) {
            if (!sibling.getId().equals(key.getId()) && sibling.isActive()) {
                sibling.setActive(false);
                keyRepository.save(sibling);
                if (sibling.getSigningCertificateId() != null) {
                    signingCertRepository.findById(sibling.getSigningCertificateId()).ifPresent(sc -> {
                        if (sc.isActive()) {
                            sc.setActive(false);
                            signingCertRepository.save(sc);
                        }
                    });
                }
            }
        }

        // 2. Deactivate any other active Signer / Key sharing the SAME HSM Token (max 1 active key per Token)
        Set<Long> targetTokenIds = new LinkedHashSet<>();
        if (key.getTokenDevice() != null && key.getTokenDevice().getId() != null) {
            targetTokenIds.add(key.getTokenDevice().getId());
        }
        if (signer.getTokens() != null) {
            signer.getTokens().stream()
                    .filter(t -> t.getTokenDevice() != null && t.getTokenDevice().getId() != null)
                    .map(t -> t.getTokenDevice().getId())
                    .forEach(targetTokenIds::add);
        }
        for (OcspSignerEntity other : signerRepository.findAll()) {
            if (!other.getId().equals(signer.getId()) && other.isActive()) {
                boolean sharesToken = other.getTokens() != null && other.getTokens().stream()
                        .anyMatch(t -> t.getTokenDevice() != null && targetTokenIds.contains(t.getTokenDevice().getId()));
                boolean certStillActive = other.getSigningCertificateId() != null
                        && signingCertRepository.findById(other.getSigningCertificateId())
                                .map(SigningCertificate::isActive)
                                .orElse(false);
                if (sharesToken || !certStillActive) {
                    if (sharesToken && certStillActive && other.getSigningCertificateId() != null) {
                        signingCertRepository.findById(other.getSigningCertificateId()).ifPresent(sc -> {
                            sc.setActive(false);
                            signingCertRepository.save(sc);
                        });
                    }
                    other.setActive(false);
                    other.setStatus("INACTIVE");
                    signerRepository.save(other);
                    for (OcspKeyEntity otherKey : keyRepository.findAllBySigner_IdOrderByIdDesc(other.getId())) {
                        if (otherKey.isActive()) {
                            otherKey.setActive(false);
                            keyRepository.save(otherKey);
                        }
                    }
                }
            }
        }

        // 3. Mark this key & signer ACTIVE
        key.setSigner(signer);
        key.setActive(true);
        key.setActivatedAt(activatedAt);
        keyRepository.save(key);

        signer.setKey(key);
        signer.setKeyLabel(key.getKeyLabel());
        signer.setKeyAlgorithm(key.getKeyAlgorithm());
        signer.setKeySize(key.getKeySize());
        signer.setSignatureAlgorithm(activated.signatureAlgorithm() != null ? activated.signatureAlgorithm() : signer.getSignatureAlgorithm());
        signer.setCertificatePem(key.getCertificatePem());
        signer.setCertSubjectDn(key.getCertSubjectDn());
        signer.setCertIssuerDn(key.getCertIssuerDn());
        signer.setCertSerialNumber(key.getCertSerialNumber());
        signer.setCertNotBefore(key.getCertNotBefore());
        signer.setCertNotAfter(key.getCertNotAfter());
        signer.setSigningCertificateId(key.getSigningCertificateId());
        signer.setActive(true);
        signer.setActivatedAt(activatedAt);
        signer.setStatus("ACTIVE");
        OcspSignerEntity saved = signerRepository.save(signer);

        log.info("Switched active key for Signer '{}' (id={}) to Key #{} ('{}')",
                saved.getCode(), saved.getId(), key.getId(), key.getKeyLabel());
        return toDto(saved, liveDevices);
    }

    /**
     * Deletes a non-active (retired or pending) key under a Signer. Active keys cannot be deleted.
     */
    @Transactional
    public void deleteSignerKey(Long signerId, Long keyId) {
        OcspSignerEntity signer = requireSigner(signerId);
        OcspKeyEntity key = keyRepository.findById(keyId)
                .orElseThrow(() -> new IllegalArgumentException("Key not found: " + keyId));
        if (key.getSigner() != null && !key.getSigner().getId().equals(signerId)) {
            throw new IllegalArgumentException("Key #" + keyId + " does not belong to signer " + signerId);
        }
        if (key.isActive() || (signer.isActive() && signer.getKey() != null && signer.getKey().getId().equals(key.getId()))) {
            throw new IllegalStateException("Cannot delete an ACTIVE key ('" + key.getKeyLabel() + "'). Activate another key or deactivate the signer first.");
        }
        if (signer.getKey() != null && signer.getKey().getId().equals(key.getId())) {
            signer.setKey(null);
            signerRepository.save(signer);
        }
        Long scId = key.getSigningCertificateId();
        keyRepository.delete(key);
        if (scId != null) {
            signingCertRepository.findById(scId).ifPresent(sc -> {
                if (!sc.isActive()) {
                    signingCertRepository.delete(sc);
                }
            });
        }
        log.info("Deleted inactive key #{} ('{}') from Signer '{}' (id={})", keyId, key.getKeyLabel(), signer.getCode(), signerId);
    }

    @Transactional
    public SignerDto activateSigner(Long id) {
        OcspSignerEntity signer = requireSigner(id);
        if (signer.getSigningCertificateId() == null || signer.getCertificatePem() == null) {
            throw new IllegalStateException("Cannot activate signer '" + signer.getCode()
                    + "': import a CA-signed certificate first (POST /signers/" + id + "/cert)");
        }

        // EJBCA rule: if HSM tokens are registered and ALL bound tokens are deactivated/LOCKED, refuse activation
        Map<String, ProviderDeviceInfo> liveDevices = mapLiveDevices();
        if (!liveDevices.isEmpty() && signer.getTokens() != null && !signer.getTokens().isEmpty()) {
            boolean anyTokenActive = signer.getTokens().stream().anyMatch(t -> {
                ProviderDeviceInfo info = liveDevices.get(t.getTokenDevice().getDeviceId());
                return info != null && DeviceActivationState.ACTIVE.name().equals(info.activationState());
            });
            if (!anyTokenActive) {
                throw new IllegalStateException("Cannot activate signer '" + signer.getCode()
                        + "': all bound HSM token(s) are deactivated/LOCKED. Unlock a token first.");
            }
        }

        SigningCertificateDto activated = signingCertificateService.activate(signer.getSigningCertificateId());

        Set<Long> myTokenIds = signer.getTokens() == null ? Set.of() : signer.getTokens().stream()
                .filter(t -> t.getTokenDevice() != null && t.getTokenDevice().getId() != null)
                .map(t -> t.getTokenDevice().getId())
                .collect(Collectors.toSet());

        // EJBCA rule: at most ONE active key/signer per HSM token — deactivate any other active signer
        // sharing a token (or whose SigningCertificate was auto-deactivated).
        for (OcspSignerEntity other : signerRepository.findAll()) {
            if (!other.getId().equals(signer.getId()) && other.isActive()) {
                boolean sharesToken = other.getTokens() != null && other.getTokens().stream()
                        .anyMatch(t -> t.getTokenDevice() != null && myTokenIds.contains(t.getTokenDevice().getId()));
                boolean certStillActive = other.getSigningCertificateId() != null
                        && signingCertRepository.findById(other.getSigningCertificateId())
                                .map(SigningCertificate::isActive)
                                .orElse(false);
                if (sharesToken || !certStillActive) {
                    if (sharesToken && certStillActive && other.getSigningCertificateId() != null) {
                        signingCertRepository.findById(other.getSigningCertificateId()).ifPresent(sc -> {
                            sc.setActive(false);
                            signingCertRepository.save(sc);
                        });
                    }
                    other.setActive(false);
                    other.setStatus("INACTIVE");
                    signerRepository.save(other);
                    log.info("Auto-deactivated OCSP Signer '{}' (id={}) — only one key/signer may be active per token",
                            other.getCode(), other.getId());
                }
            }
        }

        signer.setActive(true);
        signer.setActivatedAt(activated.activatedAt() != null ? activated.activatedAt() : Instant.now());
        signer.setStatus("ACTIVE");
        if (signer.getKey() != null) {
            OcspKeyEntity activeKey = signer.getKey();
            for (OcspKeyEntity sibling : keyRepository.findAllBySigner_IdOrderByIdDesc(signer.getId())) {
                if (!sibling.getId().equals(activeKey.getId()) && sibling.isActive()) {
                    sibling.setActive(false);
                    keyRepository.save(sibling);
                }
            }
            activeKey.setSigner(signer);
            activeKey.setActive(true);
            activeKey.setActivatedAt(signer.getActivatedAt());
            keyRepository.save(activeKey);
        }
        OcspSignerEntity saved = signerRepository.save(signer);
        return toDto(saved, liveDevices);
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
        for (OcspKeyEntity k : keyRepository.findAllBySigner_IdOrderByIdDesc(signer.getId())) {
            if (k.isActive()) {
                k.setActive(false);
                keyRepository.save(k);
            }
        }
        if (signer.getKey() != null && signer.getKey().isActive()) {
            signer.getKey().setActive(false);
            keyRepository.save(signer.getKey());
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
        Map<String, OcspSignerTokenEntity> existingByDeviceId = new java.util.HashMap<>();
        for (OcspSignerTokenEntity existing : signer.getTokens()) {
            if (existing.getTokenDevice() != null && existing.getTokenDevice().getDeviceId() != null) {
                existingByDeviceId.put(existing.getTokenDevice().getDeviceId(), existing);
            }
        }

        Set<String> wantedDeviceIds = orderedTokens.stream()
                .map(CryptoDeviceEntity::getDeviceId)
                .collect(Collectors.toSet());

        // Remove only unselected token bindings so existing bindings are updated in-place
        // (avoids Hibernate ActionQueue INSERT-before-DELETE unique constraint violation on uq_ocsp_signer_tokens)
        signer.getTokens().removeIf(t -> t.getTokenDevice() == null
                || !wantedDeviceIds.contains(t.getTokenDevice().getDeviceId()));

        for (int i = 0; i < orderedTokens.size(); i++) {
            CryptoDeviceEntity dev = orderedTokens.get(i);
            String role = (i == 0) ? "PRIMARY" : "FAILOVER";
            OcspSignerTokenEntity existing = existingByDeviceId.get(dev.getDeviceId());
            if (existing != null) {
                existing.setPriorityOrder(i);
                existing.setRole(role);
            } else {
                signer.getTokens().add(OcspSignerTokenEntity.builder()
                        .signer(signer)
                        .tokenDevice(dev)
                        .priorityOrder(i)
                        .role(role)
                        .build());
            }
        }

        signer.getTokens().sort(java.util.Comparator.comparingInt(OcspSignerTokenEntity::getPriorityOrder));
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
        OcspKeyDto keyDto = keyEntity != null ? toKeyDto(keyEntity, liveDevices, entity) : null;

        List<OcspKeyEntity> ownedKeys = entity.getId() != null
                ? keyRepository.findAllBySigner_IdOrderByIdDesc(entity.getId())
                : List.of();
        List<OcspKeyDto> keyDtos = new ArrayList<>();
        if (ownedKeys != null && !ownedKeys.isEmpty()) {
            for (OcspKeyEntity k : ownedKeys) {
                keyDtos.add(toKeyDto(k, liveDevices, entity));
            }
        } else if (keyDto != null) {
            keyDtos.add(keyDto);
        }

        List<SignerDto.SignerTokenDto> tokenDtos = new ArrayList<>();
        boolean anyTokenActive = false;
        if (entity.getTokens() != null) {
            for (OcspSignerTokenEntity t : entity.getTokens()) {
                CryptoDeviceEntity dev = t.getTokenDevice();
                CryptoProviderEntity prov = dev.getProvider();
                ProviderDeviceInfo live = liveDevices.get(dev.getDeviceId());
                String state = live != null ? live.activationState() : DeviceActivationState.LOCKED.name();
                boolean healthy = live != null && live.healthy();
                if (DeviceActivationState.ACTIVE.name().equals(state)) {
                    anyTokenActive = true;
                }
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
            effectiveStatus = (!tokenDtos.isEmpty() && !liveDevices.isEmpty() && !anyTokenActive)
                    ? "TOKEN_LOCKED"
                    : "ACTIVE";
        }

        return new SignerDto(
                entity.getId(),
                entity.getCode(),
                entity.getName(),
                effectiveStatus,
                entity.getSubjectDn(),
                keyEntity != null ? keyEntity.getId() : null,
                keyDto,
                List.copyOf(keyDtos),
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

    private static OcspKeyDto toKeyDto(
            OcspKeyEntity entity,
            Map<String, ProviderDeviceInfo> liveDevices,
            OcspSignerEntity boundSigner) {
        OcspSignerEntity effectiveSigner = entity.getSigner() != null ? entity.getSigner() : boundSigner;
        CryptoDeviceEntity td = entity.getTokenDevice();
        ProviderDeviceInfo live = td != null && liveDevices != null ? liveDevices.get(td.getDeviceId()) : null;
        String tokenState;
        if (td != null && !td.isEnabled()) {
            tokenState = "DISABLED";
        } else if (live != null && live.activationState() != null) {
            tokenState = live.activationState();
        } else {
            tokenState = DeviceActivationState.LOCKED.name();
        }
        boolean tokenActive = DeviceActivationState.ACTIVE.name().equals(tokenState);

        boolean isCurrentSignerKey = effectiveSigner != null
                && effectiveSigner.getKey() != null
                && effectiveSigner.getKey().getId() != null
                && effectiveSigner.getKey().getId().equals(entity.getId());

        String resolvedCsrPem = (entity.getCsrPem() != null && !entity.getCsrPem().isBlank())
                ? entity.getCsrPem()
                : (isCurrentSignerKey ? effectiveSigner.getCsrPem() : null);
        Instant resolvedCsrAt = entity.getCsrGeneratedAt() != null
                ? entity.getCsrGeneratedAt()
                : (isCurrentSignerKey ? effectiveSigner.getCsrGeneratedAt() : null);
        boolean hasCsr = resolvedCsrPem != null && !resolvedCsrPem.isBlank();

        String resolvedCertPem = (entity.getCertificatePem() != null && !entity.getCertificatePem().isBlank())
                ? entity.getCertificatePem()
                : (isCurrentSignerKey ? effectiveSigner.getCertificatePem() : null);
        String resolvedSerial = (entity.getCertSerialNumber() != null && !entity.getCertSerialNumber().isBlank())
                ? entity.getCertSerialNumber()
                : (isCurrentSignerKey ? effectiveSigner.getCertSerialNumber() : null);
        String resolvedIssuer = (entity.getCertIssuerDn() != null && !entity.getCertIssuerDn().isBlank())
                ? entity.getCertIssuerDn()
                : (isCurrentSignerKey ? effectiveSigner.getCertIssuerDn() : null);
        Instant resolvedNotAfter = entity.getCertNotAfter() != null
                ? entity.getCertNotAfter()
                : (isCurrentSignerKey ? effectiveSigner.getCertNotAfter() : null);
        boolean hasCert = resolvedCertPem != null && !resolvedCertPem.isBlank();

        Long daysLeft = null;
        boolean certExpired = false;
        if (hasCert && resolvedNotAfter != null) {
            Instant now = Instant.now();
            daysLeft = ChronoUnit.DAYS.between(now, resolvedNotAfter);
            certExpired = now.isAfter(resolvedNotAfter);
        }

        boolean keyActive = entity.isActive() || (isCurrentSignerKey && effectiveSigner.isActive());

        // EJBCA per-key lifecycle status:
        // - UNAVAILABLE when its HSM token is deactivated / LOCKED / DISABLED
        // - EXPIRED when its certificate is expired
        // - ACTIVE when token is ACTIVE and this is the single active key (max 1 per signer & per token)
        // - READY when token is ACTIVE and CA-signed certificate is imported (ready for 1-click cutover)
        // - CSR_PENDING when token is ACTIVE and CSR is generated awaiting CA certificate
        // - INACTIVE when token is ACTIVE and key is unbound/standby
        String keyStatus;
        if (!tokenActive) {
            keyStatus = "UNAVAILABLE";
        } else if (certExpired) {
            keyStatus = "EXPIRED";
        } else if (keyActive) {
            keyStatus = "ACTIVE";
        } else if (hasCert) {
            keyStatus = "READY";
        } else if (hasCsr) {
            keyStatus = "CSR_PENDING";
        } else {
            keyStatus = "INACTIVE";
        }

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
                entity.getCreatedAt(),
                tokenState,
                tokenActive,
                keyStatus,
                keyActive,
                effectiveSigner != null ? effectiveSigner.getId() : null,
                effectiveSigner != null ? effectiveSigner.getCode() : null,
                effectiveSigner != null ? effectiveSigner.getName() : null,
                hasCsr,
                resolvedCsrPem,
                resolvedCsrAt,
                hasCert,
                resolvedSerial,
                resolvedIssuer,
                daysLeft,
                resolvedCertPem
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
