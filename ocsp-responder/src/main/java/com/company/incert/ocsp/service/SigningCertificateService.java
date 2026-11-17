package com.company.incert.ocsp.service;

import com.company.incert.ocsp.dto.AddSigningCertificateRequest;
import com.company.incert.ocsp.dto.GenerateCsrRequest;
import com.company.incert.ocsp.dto.GenerateCsrResponse;
import com.company.incert.ocsp.dto.HsmInfoDto;
import com.company.incert.ocsp.dto.SigningCertificateDto;
import com.company.incert.ocsp.entity.SigningCertificate;
import com.company.incert.ocsp.repository.SigningCertificateRepository;
import com.company.incert.ocsp.signing.OcspSigner;
import com.company.incert.ocsp.signing.Pkcs11OcspSigner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

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

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void initDefaultCertificate() {
        Optional<SigningCertificate> activeOpt = repository.findByActiveTrue();
        if (activeOpt.isEmpty()) {
            X509CertificateHolder[] chain = ocspSigner.getSignerChain();
            if (chain != null && chain.length > 0) {
                X509CertificateHolder activeHolder = chain[0];
                String pem = toPem(activeHolder);
                String keyLabel = ocspSigner.getActiveKeyLabel();

                SigningCertificate defaultCert = SigningCertificate.builder()
                        .alias("Default OCSP Signer (" + keyLabel + ")")
                        .keyLabel(keyLabel)
                        .certificatePem(pem)
                        .subjectDn(activeHolder.getSubject().toString())
                        .issuerDn(activeHolder.getIssuer().toString())
                        .serialNumber(activeHolder.getSerialNumber().toString(16))
                        .notBefore(activeHolder.getNotBefore().toInstant())
                        .notAfter(activeHolder.getNotAfter().toInstant())
                        .signatureAlgorithm(getAlgorithm(activeHolder))
                        .active(true)
                        .activatedAt(Instant.now())
                        .build();

                repository.save(defaultCert);
                log.info("Initialized default signing certificate in database: alias='{}', keyLabel='{}', notAfter={}",
                        defaultCert.getAlias(), keyLabel, defaultCert.getNotAfter());
            }
        } else {
            SigningCertificate activeCert = activeOpt.get();
            try {
                X509CertificateHolder holder = parsePem(activeCert.getCertificatePem());
                ocspSigner.updateActiveCertificate(activeCert.getKeyLabel(), holder, activeCert.getSignatureAlgorithm());
                log.info("Synchronized active signing certificate from database: alias='{}', keyLabel='{}', algorithm='{}'",
                        activeCert.getAlias(), activeCert.getKeyLabel(), activeCert.getSignatureAlgorithm());
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
        return repository.findByActiveTrue().map(this::toDto);
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

        String keyLabel = (request.keyLabel() != null && !request.keyLabel().isBlank())
                ? request.keyLabel().trim()
                : ocspSigner.getActiveKeyLabel();

        String signatureAlgorithm = resolveSignatureAlgorithm(request.signatureAlgorithm(), holder);

        // Import and bind the signed certificate to its HSM private key if running with PKCS#11
        ocspSigner.importCertificateToToken(keyLabel, holder);

        SigningCertificate entity = SigningCertificate.builder()
                .alias(request.alias().trim())
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

        syncAllSignersWithHsmAfterCommit();
        return toDto(saved);
    }

    @Transactional
    public SigningCertificateDto activate(Long id) {
        SigningCertificate target = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Signing certificate not found with id: " + id));

        if (Instant.now().isAfter(target.getNotAfter())) {
            throw new IllegalStateException("Cannot activate an expired certificate (expired at: " + target.getNotAfter() + ")");
        }

        // Deactivate all certificates
        repository.deactivateAll();

        // Mark target active
        target.setActive(true);
        target.setActivatedAt(Instant.now());
        SigningCertificate updated = repository.save(target);

        // Update the in-memory HSM signer.
        // In production (inside a live @Transactional): defer until AFTER commit so that
        // a DB rollback cannot leave the signer and DB out of sync.
        // Outside a transaction (unit tests, batch tools): invoke synchronously.
        X509CertificateHolder holder = parsePem(updated.getCertificatePem());
        String keyLabel = updated.getKeyLabel();
        String sigAlg = updated.getSignatureAlgorithm();
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    ocspSigner.updateActiveCertificate(keyLabel, holder, sigAlg);
                    syncAllSignersWithHsm();
                    log.info("Signer updated after DB commit: keyLabel={}, algorithm={}", keyLabel, sigAlg);
                }
            });
        } else {
            ocspSigner.updateActiveCertificate(keyLabel, holder, sigAlg);
            syncAllSignersWithHsm();
            log.info("Signer updated synchronously (no active transaction): keyLabel={}, algorithm={}", keyLabel, sigAlg);
        }

        log.info("Activated signing certificate: id={}, alias='{}', keyLabel='{}', notAfter={}",
                updated.getId(), updated.getAlias(), updated.getKeyLabel(), updated.getNotAfter());

        return toDto(updated);
    }

    @Transactional
    public void delete(Long id) {
        SigningCertificate cert = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Signing certificate not found with id: " + id));

        if (cert.isActive()) {
            throw new IllegalStateException("Cannot delete the currently active signing certificate. Please activate another certificate first.");
        }

        repository.delete(cert);
        syncAllSignersWithHsmAfterCommit();
        log.info("Deleted inactive signing certificate: id={}, alias='{}'", id, cert.getAlias());
    }

    private void syncAllSignersWithHsmAfterCommit() {
        List<OcspSigner.RegisteredSigner> snapshot = buildRegisteredSignerSnapshot();
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    ocspSigner.syncRegisteredSigners(snapshot);
                }
            });
        } else {
            ocspSigner.syncRegisteredSigners(snapshot);
        }
    }

    private void syncAllSignersWithHsm() {
        ocspSigner.syncRegisteredSigners(buildRegisteredSignerSnapshot());
    }

    private List<OcspSigner.RegisteredSigner> buildRegisteredSignerSnapshot() {
        Instant now = Instant.now();
        return repository.findAll().stream()
                .filter(c -> c.getNotAfter() == null || !now.isAfter(c.getNotAfter()))
                .map(c -> {
                    try {
                        return new OcspSigner.RegisteredSigner(
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
        String alg = (request.keyAlgorithm() != null && !request.keyAlgorithm().isBlank())
                ? request.keyAlgorithm().trim().toUpperCase()
                : "RSA";
        int keySize = request.keySize() != null
                ? request.keySize()
                : ("EC".equals(alg) || "ECDSA".equals(alg) ? 256 : 3072);
        boolean reuse = Boolean.TRUE.equals(request.reuseExistingKey());

        String csrPem = ocspSigner.generateCsr(
                request.keyLabel().trim(),
                request.subjectDn().trim(),
                alg,
                keySize,
                reuse
        );
        return new GenerateCsrResponse(
                request.keyLabel().trim(),
                request.subjectDn().trim(),
                alg,
                csrPem
        );
    }

    public HsmInfoDto getHsmInfo() {
        if (ocspSigner instanceof Pkcs11OcspSigner p11) {
            return new HsmInfoDto(
                    p11.type(),
                    p11.getLibraryPath(),
                    p11.getTokenLabel(),
                    p11.getSlotListIndex(),
                    p11.getActiveKeyLabel(),
                    p11.listKeyLabels()
            );
        }
        return new HsmInfoDto(
                ocspSigner.type(),
                "N/A (Software)",
                "software",
                0,
                ocspSigner.getActiveKeyLabel(),
                ocspSigner.listKeyLabels()
        );
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

    private static final java.util.Set<String> SUPPORTED_RSA_ALGORITHMS = java.util.Set.of(
            "SHA256withRSA", "SHA384withRSA", "SHA512withRSA", "SHA256withRSAandMGF1"
    );
    private static final java.util.Set<String> SUPPORTED_EC_ALGORITHMS = java.util.Set.of(
            "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"
    );

    private String resolveSignatureAlgorithm(String requested, X509CertificateHolder holder) {
        if (requested == null || requested.isBlank()) {
            return getAlgorithm(holder);
        }
        String trimmed = requested.trim();
        boolean isEc = isEcCertificate(holder);
        if (isEc) {
            if (!SUPPORTED_EC_ALGORITHMS.contains(trimmed)) {
                throw new IllegalArgumentException("Unsupported or incompatible ECDSA signature algorithm '" + trimmed
                        + "'. Allowed: " + SUPPORTED_EC_ALGORITHMS);
            }
        } else {
            if (!SUPPORTED_RSA_ALGORITHMS.contains(trimmed)) {
                throw new IllegalArgumentException("Unsupported or incompatible RSA signature algorithm '" + trimmed
                        + "'. Allowed: " + SUPPORTED_RSA_ALGORITHMS);
            }
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

    private String getAlgorithm(X509CertificateHolder holder) {
        return isEcCertificate(holder) ? "SHA256withECDSA" : "SHA256withRSA";
    }
}

