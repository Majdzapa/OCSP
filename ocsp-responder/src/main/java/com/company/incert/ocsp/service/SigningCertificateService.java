package com.company.incert.ocsp.service;

import com.company.incert.ocsp.dto.AddSigningCertificateRequest;
import com.company.incert.ocsp.dto.SigningCertificateDto;
import com.company.incert.ocsp.entity.SigningCertificate;
import com.company.incert.ocsp.repository.SigningCertificateRepository;
import com.company.incert.ocsp.signing.OcspSigner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
                ocspSigner.updateActiveCertificate(activeCert.getKeyLabel(), holder);
                log.info("Synchronized active signing certificate from database: alias='{}', keyLabel='{}'",
                        activeCert.getAlias(), activeCert.getKeyLabel());
            } catch (Exception e) {
                log.warn("Failed to synchronize active certificate from DB with signer: {}", e.getMessage());
            }
        }
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

        SigningCertificate entity = SigningCertificate.builder()
                .alias(request.alias().trim())
                .keyLabel(keyLabel)
                .certificatePem(request.certificatePem().trim())
                .subjectDn(holder.getSubject().toString())
                .issuerDn(holder.getIssuer().toString())
                .serialNumber(holder.getSerialNumber().toString(16))
                .notBefore(notBefore)
                .notAfter(notAfter)
                .signatureAlgorithm(getAlgorithm(holder))
                .active(false)
                .build();

        SigningCertificate saved = repository.save(entity);
        log.info("Registered new signing certificate: alias='{}', keyLabel='{}', serial={}",
                saved.getAlias(), saved.getKeyLabel(), saved.getSerialNumber());

        if (Boolean.TRUE.equals(request.activateImmediately())) {
            return activate(saved.getId());
        }

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

        // Update in-memory HSM signer dynamically
        X509CertificateHolder holder = parsePem(updated.getCertificatePem());
        ocspSigner.updateActiveCertificate(updated.getKeyLabel(), holder);

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
        log.info("Deleted inactive signing certificate: id={}, alias='{}'", id, cert.getAlias());
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

    private String getAlgorithm(X509CertificateHolder holder) {
        try {
            if (holder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId().contains("1.2.840.10045")) {
                return "SHA256withECDSA";
            }
        } catch (Exception ignored) {}
        return "SHA256withRSA";
    }
}

