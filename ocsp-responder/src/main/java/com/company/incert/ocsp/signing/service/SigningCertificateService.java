package com.company.incert.ocsp.signing.service;

import com.company.incert.ocsp.signing.dto.AddSigningCertificateRequest;
import com.company.incert.ocsp.signing.dto.GenerateCsrRequest;
import com.company.incert.ocsp.signing.dto.GenerateCsrResponse;
import com.company.incert.ocsp.signing.dto.HsmInfoDto;
import com.company.incert.ocsp.signing.dto.SigningCertificateDto;
import com.company.incert.ocsp.signing.entity.SigningCertificate;
import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
import com.company.incert.ocsp.signing.repository.SigningCertificateRepository;
import com.company.incert.ocsp.signing.hsm.OcspSigner;
import com.company.incert.ocsp.signing.hsm.SigningAlgorithm;
import com.company.incert.ocsp.signing.usecase.FindSigningCertificateUseCase;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.io.StringReader;
import java.io.StringWriter;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class SigningCertificateService {

    private final SigningCertificateRepository repository;
    private final OcspSigner ocspSigner;
    private final ApplicationEventPublisher eventPublisher;
    private final FindSigningCertificateUseCase findSigningCertificate;

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
        if (repository.existsByAlias(request.alias())) {
            throw new IllegalArgumentException("Signing certificate with alias '" + request.alias() + "' already exists");
        }

        X509CertificateHolder holder = parsePem(request.certificatePem());
        Instant notBefore = holder.getNotBefore().toInstant();
        Instant notAfter = holder.getNotAfter().toInstant();

        if (Instant.now().isAfter(notAfter)) {
            throw new IllegalArgumentException("Cannot add an expired signing certificate (expired at: " + notAfter + ")");
        }

        String providerId = resolveProviderId(request.providerId());
        String keyLabel = (request.keyLabel() != null && !request.keyLabel().isBlank())
                ? request.keyLabel().trim()
                : ocspSigner.getActiveKeyLabel();

        String signatureAlgorithm = resolveSignatureAlgorithm(request.signatureAlgorithm(), holder);

        // Import and bind the signed certificate to its HSM private key on the target provider
        ocspSigner.importCertificateToToken(providerId, keyLabel, holder);

        SigningCertificate entity = SigningCertificate.builder()
                .alias(request.alias().trim())
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

        if (Boolean.TRUE.equals(request.activateImmediately())) {
            return activate(saved.getId());
        }

        publishSignerStateRefresh();
        return toDto(saved);
    }

    @Transactional
    public SigningCertificateDto activate(Long id) {
        SigningCertificate target = findSigningCertificate.execute(id);

        if (Instant.now().isAfter(target.getNotAfter())) {
            throw new IllegalStateException("Cannot activate an expired certificate (expired at: " + target.getNotAfter() + ")");
        }

        List<String> hsmKeys = ocspSigner.listKeyLabels(target.getProviderId());
        if (!hsmKeys.isEmpty() && !hsmKeys.contains(target.getKeyLabel())) {
            throw new IllegalStateException("Cannot activate certificate '" + target.getAlias()
                    + "': HSM key '" + target.getKeyLabel() + "' not found on provider '" + target.getProviderId() + "'");
        }

        // Mark target active (multiple signing certificates can be active simultaneously, e.g. one per CA/device)
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
        return repository.findAll().stream()
                .filter(SigningCertificate::isActive)
                .filter(c -> c.getNotAfter() == null || !now.isAfter(c.getNotAfter()))
                .map(c -> {
                    try {
                        return new OcspSigner.RegisteredSigner(
                                c.getProviderId(),
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
        String alg = (request.keyAlgorithm() != null && !request.keyAlgorithm().isBlank())
                ? request.keyAlgorithm().trim().toUpperCase()
                : "RSA";
        int keySize = request.keySize() != null
                ? request.keySize()
                : ("EC".equals(alg) || "ECDSA".equals(alg) ? 256 : 3072);
        boolean reuse = Boolean.TRUE.equals(request.reuseExistingKey());

        String csrPem = ocspSigner.generateCsr(
                providerId,
                request.keyLabel().trim(),
                request.subjectDn().trim(),
                alg,
                keySize,
                reuse
        );
        return new GenerateCsrResponse(
                providerId,
                request.keyLabel().trim(),
                request.subjectDn().trim(),
                alg,
                csrPem
        );
    }

    public List<ProviderDeviceInfo> listProviders() {
        return ocspSigner.listProviders();
    }

    public HsmInfoDto getHsmInfo() {
        java.util.Map<String, java.util.List<String>> supportedByType = SigningAlgorithm.groupedByKeyType();
        List<ProviderDeviceInfo> providers = ocspSigner.listProviders();
        String defaultProviderId = resolveProviderId(null);

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

    private String resolveSignatureAlgorithm(String requested, X509CertificateHolder holder) {
        String keyType = isEcCertificate(holder) ? "EC" : "RSA";
        if (requested == null || requested.isBlank()) {
            return SigningAlgorithm.defaultForKeyType(keyType).getAlgorithmName();
        }
        String trimmed = requested.trim();
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

