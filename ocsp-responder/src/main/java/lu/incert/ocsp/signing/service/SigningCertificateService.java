package lu.incert.ocsp.signing.service;

import lu.incert.ocsp.signing.dto.AddSigningCertificateRequest;
import lu.incert.ocsp.signing.dto.AlgorithmCheckRequest;
import lu.incert.ocsp.signing.dto.GenerateCsrRequest;
import lu.incert.ocsp.signing.dto.GenerateCsrResponse;
import lu.incert.ocsp.signing.dto.HsmInfoDto;
import lu.incert.ocsp.signing.dto.SigningCertificateDto;
import lu.incert.ocsp.signing.entity.OcspKeyEntity;
import lu.incert.ocsp.signing.entity.OcspSignerEntity;
import lu.incert.ocsp.signing.entity.SigningCertificate;
import lu.incert.ocsp.signing.port.ProviderCapabilities;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import lu.incert.ocsp.signing.repository.OcspKeyRepository;
import lu.incert.ocsp.signing.repository.OcspSignerRepository;
import lu.incert.ocsp.signing.repository.SigningCertificateRepository;
import lu.incert.ocsp.signing.hsm.CaSignerMatcher;
import lu.incert.ocsp.signing.hsm.OcspSigner;
import lu.incert.ocsp.signing.hsm.SigningAlgorithm;
import lu.incert.ocsp.signing.usecase.FindSigningCertificateUseCase;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
public class SigningCertificateService {

    private final SigningCertificateRepository repository;
    private final OcspSigner ocspSigner;
    private final ApplicationEventPublisher eventPublisher;
    private final FindSigningCertificateUseCase findSigningCertificate;
    private final OcspSignerRepository signerRepository;
    private final OcspKeyRepository keyRepository;

    public SigningCertificateService(
            SigningCertificateRepository repository,
            OcspSigner ocspSigner,
            ApplicationEventPublisher eventPublisher,
            FindSigningCertificateUseCase findSigningCertificate) {
        this(repository, ocspSigner, eventPublisher, findSigningCertificate, null, null);
    }

    public SigningCertificateService(
            SigningCertificateRepository repository,
            OcspSigner ocspSigner,
            ApplicationEventPublisher eventPublisher,
            FindSigningCertificateUseCase findSigningCertificate,
            OcspSignerRepository signerRepository) {
        this(repository, ocspSigner, eventPublisher, findSigningCertificate, signerRepository, null);
    }

    @Autowired
    public SigningCertificateService(
            SigningCertificateRepository repository,
            OcspSigner ocspSigner,
            ApplicationEventPublisher eventPublisher,
            FindSigningCertificateUseCase findSigningCertificate,
            @Autowired(required = false) OcspSignerRepository signerRepository,
            @Autowired(required = false) OcspKeyRepository keyRepository) {
        this.repository = repository;
        this.ocspSigner = ocspSigner;
        this.eventPublisher = eventPublisher;
        this.findSigningCertificate = findSigningCertificate;
        this.signerRepository = signerRepository;
        this.keyRepository = keyRepository;
    }

    /** Publishes a "no active signer / just resync with the HSM" event (repeated across flows). */
    private void publishSignerStateRefresh() {
        eventPublisher.publishEvent(new SigningConfigurationChangedEvent(null, null, null, null, false));
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void initDefaultCertificate() {
        // No default signing certificate is ever created: signing certificates are configured by the user
        // (generate CSR in the HSM -> issue from a CA -> import -> activate).
        List<SigningCertificate> activeList = repository.findAllByActiveTrueOrderByActivatedAtDesc();
        if (activeList.isEmpty()) {
            log.info("No active signing certificate configured; OCSP requests answer tryLater until one is activated");
        } else {
            SigningCertificate primary = activeList.get(0);
            try {
                X509CertificateHolder holder = parsePem(primary.getCertificatePem());
                ocspSigner.updateActiveCertificate(
                        primary.getProviderId(), primary.getKeyLabel(), holder, primary.getSignatureAlgorithm());
                log.info("Synchronized {} active signing certificate(s) from database (primary alias='{}', provider='{}', keyLabel='{}', algorithm='{}')",
                        activeList.size(), primary.getAlias(), primary.getProviderId(), primary.getKeyLabel(), primary.getSignatureAlgorithm());
            } catch (Exception e) {
                log.warn("Failed to synchronize active certificate from DB with signer: {}", e.getMessage());
            }
        }
        syncAllSignersWithHsm();
    }

    @Transactional(readOnly = true)
    public List<SigningCertificateDto> listAll() {
        return repository.findAll().stream()
                .map(this::toDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public Optional<SigningCertificateDto> getActiveCertificate() {
        return repository.findAllByActiveTrueOrderByActivatedAtDesc().stream()
                .findFirst()
                .map(this::toDto);
    }

    @Transactional
    public SigningCertificateDto addCertificate(AddSigningCertificateRequest request) {
        OcspSignerEntity targetSigner = null;
        if (request.signerId() != null && signerRepository != null) {
            targetSigner = signerRepository.findById(request.signerId())
                    .orElseThrow(() -> new IllegalArgumentException("Signer not found: " + request.signerId()));
        }

        String rawAlias = (request.alias() != null && !request.alias().isBlank())
                ? request.alias().trim()
                : (targetSigner != null ? targetSigner.getCode() : null);
        if (rawAlias == null || rawAlias.isBlank()) {
            throw new IllegalArgumentException("Alias (or signerId) is required");
        }

        if (targetSigner != null && targetSigner.getSigningCertificateId() != null) {
            repository.findById(targetSigner.getSigningCertificateId()).ifPresent(existing -> {
                if (!existing.isActive()) {
                    repository.delete(existing);
                    repository.flush();
                }
            });
        }

        String resolvedAlias = rawAlias;
        if (repository.existsByAlias(resolvedAlias)) {
            if (targetSigner != null) {
                resolvedAlias = targetSigner.getCode() + "-" + (System.currentTimeMillis() % 100000);
            } else {
                throw new IllegalArgumentException("Signing certificate with alias '" + resolvedAlias + "' already exists");
            }
        }

        X509CertificateHolder holder = parsePem(request.certificatePem());
        Instant notBefore = holder.getNotBefore().toInstant();
        Instant notAfter = holder.getNotAfter().toInstant();

        if (Instant.now().isAfter(notAfter)) {
            throw new IllegalArgumentException("Cannot add an expired signing certificate (expired at: " + notAfter + ")");
        }

        // RFC 6960 §2.6: delegated OCSP signer certificates must include id-kp-OCSPSigning EKU
        // (unless the Issuing CA itself is signing directly with a CA certificate).
        boolean isCaCert = CaSignerMatcher.isCaCertificate(holder);
        boolean hasOcspEku = CaSignerMatcher.hasOcspSigningEku(holder);
        if (!isCaCert && !hasOcspEku) {
            throw new IllegalArgumentException(
                    "Certificate is not authorized for OCSP signing (RFC 6960 §2.6): "
                            + "a delegated OCSP Signer certificate must include Extended Key Usage "
                            + "'id-kp-OCSPSigning' (1.3.6.1.5.5.7.3.9), or be a CA certificate (BasicConstraints cA=true)");
        }
        if (!isCaCert && !CaSignerMatcher.hasOcspNoCheckExtension(holder)) {
            log.warn("Imported delegated OCSP signing certificate '{}' does not include the recommended "
                    + "id-pkix-ocsp-nocheck extension (RFC 6960 §4.2.2.2.1)", resolvedAlias);
        }

        String providerId;
        if (targetSigner != null && !targetSigner.getTokens().isEmpty()) {
            providerId = resolveFirstActiveOrPrimaryToken(targetSigner);
        } else {
            providerId = resolveProviderId(request.providerId());
        }

        String keyLabel;
        if (targetSigner != null && targetSigner.getKey() != null) {
            keyLabel = targetSigner.getKey().getKeyLabel();
        } else if (targetSigner != null && targetSigner.getKeyLabel() != null && !targetSigner.getKeyLabel().isBlank()) {
            keyLabel = targetSigner.getKeyLabel();
        } else if (request.keyLabel() != null && !request.keyLabel().isBlank()) {
            keyLabel = request.keyLabel().trim();
        } else {
            keyLabel = ocspSigner.getActiveKeyLabel();
        }

        String requestedSigAlg = (request.signatureAlgorithm() != null && !request.signatureAlgorithm().isBlank())
                ? request.signatureAlgorithm().trim()
                : (targetSigner != null ? targetSigner.getSignatureAlgorithm() : null);
        String signatureAlgorithm = resolveSignatureAlgorithm(requestedSigAlg, holder, providerId, keyLabel);

        // Zero-token-touch public-key verification when OcspKeyEntity (or Signer CSR) exists in DB!
        Optional<OcspKeyEntity> persistedKey = (targetSigner != null && targetSigner.getKey() != null)
                ? Optional.of(targetSigner.getKey())
                : (keyRepository != null ? keyRepository.findByKeyLabel(keyLabel) : Optional.empty());

        if (persistedKey.isPresent()) {
            verifyCertificateMatchesSpki(holder, parsePublicKeyPem(persistedKey.get().getPublicKeyPem()), keyLabel);
        } else if (targetSigner != null) {
            if (targetSigner.getCsrPem() != null && !targetSigner.getCsrPem().isBlank()) {
                SubjectPublicKeyInfo csrSpki = extractPublicKeyFromCsrPem(targetSigner.getCsrPem());
                if (csrSpki != null) {
                    verifyCertificateMatchesSpki(holder, csrSpki, keyLabel);
                }
            }
        } else {
            // Legacy fallback when no OcspKeyEntity / Signer aggregate exists
            ocspSigner.importCertificateToToken(providerId, keyLabel, holder);
        }

        SigningCertificate entity = SigningCertificate.builder()
                .alias(resolvedAlias)
                .providerId(providerId)
                .keyLabel(keyLabel)
                .certificatePem(request.certificatePem().trim())
                .subjectDn(holder.getSubject().toString())
                .issuerDn(holder.getIssuer().toString())
                .serialNumber(holder.getSerialNumber().toString(16))
                .notBefore(notBefore)
                .notAfter(notAfter)
                .signatureAlgorithm(signatureAlgorithm)
                .active(false)
                .build();

        SigningCertificate saved = repository.save(entity);
        log.info("Registered new signing certificate: alias='{}', keyLabel='{}', serial={}",
                saved.getAlias(), saved.getKeyLabel(), saved.getSerialNumber());

        if (targetSigner != null) {
            targetSigner.setSignatureAlgorithm(saved.getSignatureAlgorithm());
            targetSigner.setCertificatePem(saved.getCertificatePem());
            targetSigner.setCertSubjectDn(saved.getSubjectDn());
            targetSigner.setCertIssuerDn(saved.getIssuerDn());
            targetSigner.setCertSerialNumber(saved.getSerialNumber());
            targetSigner.setCertNotBefore(saved.getNotBefore());
            targetSigner.setCertNotAfter(saved.getNotAfter());
            targetSigner.setSigningCertificateId(saved.getId());
            targetSigner.setStatus("CERT_IMPORTED");
            signerRepository.save(targetSigner);
        }

        if (Boolean.TRUE.equals(request.activateImmediately())) {
            SigningCertificateDto activated = activate(saved.getId());
            if (targetSigner != null) {
                targetSigner.setActive(true);
                targetSigner.setActivatedAt(activated.activatedAt());
                targetSigner.setStatus("ACTIVE");
                signerRepository.save(targetSigner);
            }
            return activated;
        }

        publishSignerStateRefresh();
        return toDto(saved);
    }

    private String resolveFirstActiveOrPrimaryToken(OcspSignerEntity signer) {
        java.util.Map<String, ProviderDeviceInfo> live = ocspSigner.listProviders().stream()
                .collect(java.util.stream.Collectors.toMap(ProviderDeviceInfo::providerId, p -> p, (a, b) -> a));
        for (var t : signer.getTokens()) {
            String devId = t.getTokenDevice().getDeviceId();
            ProviderDeviceInfo info = live.get(devId);
            if (info != null && "ACTIVE".equals(info.activationState())) {
                return devId;
            }
        }
        return signer.getTokens().get(0).getTokenDevice().getDeviceId();
    }

    @Transactional
    public SigningCertificateDto activate(Long id) {
        SigningCertificate target = findSigningCertificate.execute(id);

        if (Instant.now().isAfter(target.getNotAfter())) {
            throw new IllegalStateException("Cannot activate an expired certificate (expired at: " + target.getNotAfter() + ")");
        }

        Optional<OcspKeyEntity> persistedKey = keyRepository != null
                ? keyRepository.findByKeyLabel(target.getKeyLabel())
                : Optional.empty();

        if (persistedKey.isEmpty()) {
            List<String> hsmKeys = ocspSigner.listKeyLabels(target.getProviderId());
            if (!hsmKeys.isEmpty() && !hsmKeys.contains(target.getKeyLabel())) {
                throw new IllegalStateException("Cannot activate certificate '" + target.getAlias()
                        + "': HSM key '" + target.getKeyLabel() + "' not found on provider '" + target.getProviderId() + "'");
            }
        }

        // Verify live HSM supports this certificate's signature algorithm and key type (0 token object queries when key is in DB)
        String targetProvider = resolveProviderId(target.getProviderId());
        ProviderCapabilities liveCaps = ocspSigner.getProviderCapabilities(targetProvider);
        if (liveCaps != null && liveCaps.liveIntrospected()) {
            String knownKeyAlg = persistedKey.map(OcspKeyEntity::getKeyAlgorithm).orElse(null);
            Integer knownKeySize = persistedKey.map(OcspKeyEntity::getKeySize).orElse(null);
            ProviderCapabilities.AlgorithmValidationResult check = ocspSigner.checkAlgorithmSupport(
                    targetProvider, target.getKeyLabel(), knownKeyAlg, knownKeySize, target.getSignatureAlgorithm());
            if (check != null && !check.supported()) {
                throw new IllegalStateException("Cannot activate certificate '" + target.getAlias()
                        + "': " + check.message());
            }
        }

        // EJBCA rule: at most ONE active signing key/certificate per HSM token (and per Issuing CA)
        for (SigningCertificate existing : repository.findAllByActiveTrueOrderByActivatedAtDesc()) {
            if (!existing.getId().equals(target.getId())) {
                boolean sameIssuer = existing.getIssuerDn() != null && existing.getIssuerDn().equals(target.getIssuerDn());
                boolean sameToken = java.util.Objects.equals(
                        resolveProviderId(existing.getProviderId()), resolveProviderId(target.getProviderId()));
                boolean sameKey = existing.getKeyLabel() != null && existing.getKeyLabel().equals(target.getKeyLabel())
                        && sameToken;
                if (sameIssuer || sameToken || sameKey) {
                    existing.setActive(false);
                    repository.save(existing);
                    log.info("Auto-deactivated superseded signing certificate id={}, alias='{}' (sameIssuer={}, sameToken={}, sameKey={})",
                            existing.getId(), existing.getAlias(), sameIssuer, sameToken, sameKey);
                }
            }
        }

        // Mark target active (multiple signing certificates can be active simultaneously across different CAs/devices)
        target.setActive(true);
        target.setActivatedAt(Instant.now());
        SigningCertificate updated = repository.save(target);

        X509CertificateHolder holder = parsePem(updated.getCertificatePem());
        eventPublisher.publishEvent(new SigningConfigurationChangedEvent(
                updated.getProviderId(), updated.getKeyLabel(), holder, updated.getSignatureAlgorithm(), true));

        log.info("Activated signing certificate: id={}, alias='{}', provider='{}', keyLabel='{}', notAfter={}",
                updated.getId(), updated.getAlias(), updated.getProviderId(), updated.getKeyLabel(), updated.getNotAfter());

        return toDto(updated);
    }

    @Transactional
    public SigningCertificateDto deactivate(Long id) {
        SigningCertificate target = findSigningCertificate.execute(id);

        if (!target.isActive()) {
            return toDto(target);
        }

        if (repository.countByActiveTrue() <= 1) {
            throw new IllegalStateException("Cannot deactivate the last remaining active signing certificate");
        }

        target.setActive(false);
        SigningCertificate updated = repository.save(target);

        List<SigningCertificate> remainingActive = repository.findAllByActiveTrueOrderByActivatedAtDesc();
        SigningCertificate fallback = remainingActive.isEmpty() ? null : remainingActive.get(0);
        if (fallback != null) {
            eventPublisher.publishEvent(new SigningConfigurationChangedEvent(
                    fallback.getProviderId(),
                    fallback.getKeyLabel(),
                    parsePem(fallback.getCertificatePem()),
                    fallback.getSignatureAlgorithm(),
                    true));
        } else {
            publishSignerStateRefresh();
        }

        log.info("Deactivated signing certificate: id={}, alias='{}'", updated.getId(), updated.getAlias());
        return toDto(updated);
    }

    @Transactional
    public void delete(Long id) {
        SigningCertificate cert = findSigningCertificate.execute(id);

        if (cert.isActive()) {
            throw new IllegalStateException("Cannot delete the currently active signing certificate. Please activate another certificate first.");
        }

        repository.delete(cert);
        publishSignerStateRefresh();
        log.info("Deleted inactive signing certificate: id={}, alias='{}'", id, cert.getAlias());
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onSigningConfigurationChanged(SigningConfigurationChangedEvent event) {
        if (event.activateDefault() && event.holder() != null) {
            ocspSigner.updateActiveCertificate(
                    event.providerId(), event.keyLabel(), event.holder(), event.signatureAlgorithm());
            log.info("Signer updated after DB commit: provider={}, keyLabel={}, algorithm={}",
                    event.providerId(), event.keyLabel(), event.signatureAlgorithm());
        }
        syncAllSignersWithHsm();
    }

    public record SigningConfigurationChangedEvent(
            String providerId,
            String keyLabel,
            X509CertificateHolder holder,
            String signatureAlgorithm,
            boolean activateDefault
    ) {
        public SigningConfigurationChangedEvent(
                String keyLabel,
                X509CertificateHolder holder,
                String signatureAlgorithm,
                boolean activateDefault) {
            this("default", keyLabel, holder, signatureAlgorithm, activateDefault);
        }
    }

    private void syncAllSignersWithHsm() {
        ocspSigner.syncRegisteredSigners(buildRegisteredSignerSnapshot());
    }

    private List<OcspSigner.RegisteredSigner> buildRegisteredSignerSnapshot() {
        Instant now = Instant.now();
        return repository.findAllByActiveTrueOrderByActivatedAtDesc().stream()
                .filter(c -> c.getNotAfter() == null || !now.isAfter(c.getNotAfter()))
                .map(c -> {
                    try {
                        List<String> orderedTokens = List.of(c.getProviderId());
                        if (signerRepository != null && c.getId() != null) {
                            Optional<OcspSignerEntity> linked = signerRepository.findBySigningCertificateId(c.getId());
                            if (linked.isPresent() && linked.get().getTokens() != null && !linked.get().getTokens().isEmpty()) {
                                orderedTokens = linked.get().getTokens().stream()
                                        .map(t -> t.getTokenDevice().getDeviceId())
                                        .toList();
                            }
                        }
                        return new OcspSigner.RegisteredSigner(
                                c.getProviderId(),
                                orderedTokens,
                                c.getKeyLabel(),
                                parsePem(c.getCertificatePem()),
                                c.isActive(),
                                c.getSignatureAlgorithm()
                        );
                    } catch (Exception e) {
                        log.warn("Skipping unparseable signing certificate alias='{}': {}", c.getAlias(), e.getMessage());
                        return null;
                    }
                })
                .filter(java.util.Objects::nonNull)
                .toList();
    }

    public GenerateCsrResponse generateCsr(GenerateCsrRequest request) {
        String providerId = resolveProviderId(request.providerId());
        boolean reuse = Boolean.TRUE.equals(request.reuseExistingKey());
        String alg = (request.keyAlgorithm() != null && !request.keyAlgorithm().isBlank())
                ? request.keyAlgorithm().trim().toUpperCase()
                : (reuse ? null : "RSA");
        int keySize = request.keySize() != null
                ? request.keySize()
                : (alg != null && ("EC".equals(alg) || "ECDSA".equals(alg)) ? 256 : 3072);
        String sigAlg = (request.signatureAlgorithm() != null && !request.signatureAlgorithm().isBlank())
                ? request.signatureAlgorithm().trim()
                : null;

        // Pre-verify key algorithm, key size, and chosen CSR signing algorithm against live HSM capabilities
        ProviderCapabilities liveCaps = ocspSigner.getProviderCapabilities(providerId);
        if (liveCaps != null && liveCaps.liveIntrospected()) {
            ProviderCapabilities.AlgorithmValidationResult check = ocspSigner.checkAlgorithmSupport(
                    providerId,
                    reuse ? request.keyLabel().trim() : null,
                    reuse ? null : alg,
                    reuse ? null : keySize,
                    sigAlg
            );
            if (check != null && !check.supported()) {
                throw new IllegalArgumentException(check.message());
            }
        }

        String csrPem = ocspSigner.generateCsr(
                providerId,
                request.keyLabel().trim(),
                request.subjectDn().trim(),
                alg != null ? alg : "RSA",
                keySize,
                sigAlg,
                reuse
        );
        return new GenerateCsrResponse(
                providerId,
                request.keyLabel().trim(),
                request.subjectDn().trim(),
                alg != null ? alg : "EXISTING",
                csrPem
        );
    }

    public ProviderCapabilities getProviderCapabilities(String providerId) {
        String resolved = resolveProviderId(providerId);
        return ocspSigner.getProviderCapabilities(resolved);
    }

    public ProviderCapabilities.AlgorithmValidationResult checkAlgorithmSupport(AlgorithmCheckRequest request) {
        String resolved = resolveProviderId(request != null ? request.providerId() : null);
        return ocspSigner.checkAlgorithmSupport(
                resolved,
                request != null ? request.keyLabel() : null,
                request != null ? request.keyAlgorithm() : null,
                request != null ? request.keySize() : null,
                request != null ? request.signatureAlgorithm() : null
        );
    }

    public List<ProviderDeviceInfo> listProviders() {
        return ocspSigner.listProviders();
    }

    public HsmInfoDto getHsmInfo() {
        List<ProviderDeviceInfo> providers = ocspSigner.listProviders();
        String defaultProviderId = resolveProviderId(null);
        java.util.Map<String, java.util.List<String>> supportedByType = SigningAlgorithm.groupedByKeyType();
        try {
            ProviderCapabilities caps = ocspSigner.getProviderCapabilities(defaultProviderId);
            if (caps != null && caps.liveIntrospected() && caps.supportedSignatureAlgorithms() != null
                    && !caps.supportedSignatureAlgorithms().isEmpty()) {
                supportedByType = caps.supportedSignatureAlgorithms();
            }
        } catch (Exception ignored) {
            // Provider may still be LOCKED (Pattern 2); keep registered strategy list as fallback
        }

        ProviderDeviceInfo primaryInfo = providers.stream()
                .filter(p -> defaultProviderId.equals(p.providerId()))
                .findFirst()
                .orElse(providers.isEmpty() ? null : providers.get(0));

        if (primaryInfo != null) {
            java.util.Map<String, String> mergedKeyAlgs = new java.util.LinkedHashMap<>();
            providers.stream()
                    .map(ProviderDeviceInfo::keyAlgorithms)
                    .filter(java.util.Objects::nonNull)
                    .forEach(mergedKeyAlgs::putAll);
            return new HsmInfoDto(
                    ocspSigner.type(),
                    primaryInfo.libraryPath(),
                    primaryInfo.tokenLabel(),
                    (int) primaryInfo.slotId(),
                    ocspSigner.getActiveKeyLabel(),
                    primaryInfo.keyLabels() != null ? primaryInfo.keyLabels() : ocspSigner.listKeyLabels(),
                    mergedKeyAlgs,
                    supportedByType,
                    defaultProviderId,
                    providers
            );
        }
        return new HsmInfoDto(
                ocspSigner.type(),
                "N/A (Software)",
                "software",
                0,
                ocspSigner.getActiveKeyLabel(),
                ocspSigner.listKeyLabels(),
                ocspSigner.getKeyAlgorithms(),
                supportedByType,
                defaultProviderId,
                providers
        );
    }

    private String resolveProviderId(String requestedProviderId) {
        if (requestedProviderId != null && !requestedProviderId.isBlank()
                && !"default".equalsIgnoreCase(requestedProviderId.trim())) {
            return requestedProviderId.trim();
        }
        String signerDefault = ocspSigner.getDefaultProviderId();
        return (signerDefault != null && !signerDefault.isBlank()) ? signerDefault.trim() : "default";
    }

    private SigningCertificateDto toDto(SigningCertificate entity) {
        Instant now = Instant.now();
        long daysUntilExpiry = entity.getNotAfter() != null
                ? ChronoUnit.DAYS.between(now, entity.getNotAfter())
                : -1;
        boolean expired = entity.getNotAfter() != null && now.isAfter(entity.getNotAfter());

        return SigningCertificateDto.builder()
                .id(entity.getId())
                .alias(entity.getAlias())
                .providerId(entity.getProviderId())
                .keyLabel(entity.getKeyLabel())
                .subjectDn(entity.getSubjectDn())
                .issuerDn(entity.getIssuerDn())
                .serialNumber(entity.getSerialNumber())
                .notBefore(entity.getNotBefore())
                .notAfter(entity.getNotAfter())
                .signatureAlgorithm(entity.getSignatureAlgorithm())
                .active(entity.isActive())
                .daysUntilExpiry(daysUntilExpiry)
                .expired(expired)
                .createdAt(entity.getCreatedAt())
                .activatedAt(entity.getActivatedAt())
                .certificatePem(entity.getCertificatePem())
                .build();
    }

    public static X509CertificateHolder parsePem(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder holder) {
                return holder;
            }
            throw new IllegalArgumentException("Provided content is not a valid PEM encoded X.509 certificate");
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse certificate PEM: " + e.getMessage(), e);
        }
    }

    public static String toPem(X509CertificateHolder cert) {
        try (StringWriter sw = new StringWriter(); JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(cert);
            writer.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to format certificate as PEM: " + e.getMessage(), e);
        }
    }

    public static String toPublicKeyPem(SubjectPublicKeyInfo spki) {
        try (StringWriter sw = new StringWriter(); PemWriter writer = new PemWriter(sw)) {
            writer.writeObject(new PemObject("PUBLIC KEY", spki.getEncoded()));
            writer.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to format SubjectPublicKeyInfo as PEM: " + e.getMessage(), e);
        }
    }

    public static SubjectPublicKeyInfo parsePublicKeyPem(String pem) {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object obj = parser.readObject();
            if (obj instanceof SubjectPublicKeyInfo spki) {
                return spki;
            }
            throw new IllegalArgumentException("Provided content is not a valid PEM SubjectPublicKeyInfo");
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse public key PEM: " + e.getMessage(), e);
        }
    }

    public static SubjectPublicKeyInfo extractPublicKeyFromCsrPem(String csrPem) {
        if (csrPem == null || csrPem.isBlank()) {
            return null;
        }
        try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
            Object obj = parser.readObject();
            if (obj instanceof PKCS10CertificationRequest csr) {
                return csr.getSubjectPublicKeyInfo();
            }
        } catch (Exception ignored) {}
        try (org.bouncycastle.util.io.pem.PemReader reader =
                     new org.bouncycastle.util.io.pem.PemReader(new StringReader(csrPem))) {
            PemObject pemObj = reader.readPemObject();
            if (pemObj != null && pemObj.getContent() != null) {
                return new PKCS10CertificationRequest(pemObj.getContent()).getSubjectPublicKeyInfo();
            }
        } catch (Exception ignored) {}
        return null;
    }

    public static String computePublicKeySha1Hex(SubjectPublicKeyInfo spki) {
        try {
            byte[] rawBits = spki.getPublicKeyData().getBytes();
            byte[] digest = MessageDigest.getInstance("SHA-1").digest(rawBits);
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute SHA-1 of SubjectPublicKeyInfo", e);
        }
    }

    public static void verifyCertificateMatchesSpki(
            X509CertificateHolder certHolder,
            SubjectPublicKeyInfo expectedSpki,
            String keyLabel) {
        try {
            if (!Arrays.equals(expectedSpki.getEncoded(), certHolder.getSubjectPublicKeyInfo().getEncoded())) {
                throw new IllegalArgumentException(
                        "Imported certificate public key does not match private key '" + keyLabel + "'");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed comparing certificate public key against persisted key", e);
        }
    }

    private String resolveSignatureAlgorithm(
            String requested,
            X509CertificateHolder holder,
            String providerId,
            String keyLabel) {
        String keyType = isEcCertificate(holder) ? "EC" : "RSA";
        ProviderCapabilities liveCaps = null;
        try {
            liveCaps = ocspSigner.getProviderCapabilities(providerId);
        } catch (Exception ignored) {}

        if (requested == null || requested.isBlank()) {
            if (liveCaps != null && liveCaps.liveIntrospected()) {
                List<String> liveSupported = liveCaps.supportedSignatureAlgorithms().getOrDefault(keyType, List.of());
                if (!liveSupported.isEmpty()) {
                    return liveSupported.get(0);
                }
                throw new IllegalArgumentException(
                        "No signing algorithms for key type " + keyType + " are supported on HSM provider '" + providerId + "'");
            }
            return SigningAlgorithm.defaultForKeyType(keyType).getAlgorithmName();
        }
        String trimmed = requested.trim();
        if (liveCaps != null && liveCaps.liveIntrospected()) {
            ProviderCapabilities.AlgorithmValidationResult check =
                    ocspSigner.checkAlgorithmSupport(providerId, keyLabel, keyType, null, trimmed);
            if (check != null && !check.supported()) {
                throw new IllegalArgumentException(check.message());
            }
            return trimmed;
        }
        if (!SigningAlgorithm.isSupportedForKeyType(trimmed, keyType)) {
            throw new IllegalArgumentException("Unsupported or incompatible " + keyType + " signature algorithm '" + trimmed
                    + "'. Allowed: " + SigningAlgorithm.namesForKeyType(keyType));
        }
        return trimmed;
    }

    private boolean isEcCertificate(X509CertificateHolder holder) {
        try {
            AlgorithmIdentifier algId = holder.getSubjectPublicKeyInfo().getAlgorithm();
            return X9ObjectIdentifiers.id_ecPublicKey.equals(algId.getAlgorithm());
        } catch (Exception ignored) {
            return false;
        }
    }
}

