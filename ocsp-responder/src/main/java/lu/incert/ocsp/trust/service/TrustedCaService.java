package lu.incert.ocsp.trust.service;

import lu.incert.ocsp.shared.usecase.CanonicalizeSerialHexUseCase;
import lu.incert.ocsp.trust.dto.TrustedCaDto;
import lu.incert.ocsp.trust.entity.TrustedCaEntity;
import lu.incert.ocsp.trust.repository.TrustedCaRepository;
import lu.incert.ocsp.trust.tls.TrustedCasReloadedEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages Trusted CA certificates and maintains a hot-reloaded in-memory X.509 truststore.
 * Importing, enabling, disabling, or deleting a CA takes effect immediately without restarting the app.
 */
@Slf4j
@Service
public class TrustedCaService {

    private static final HexFormat HEX = HexFormat.of();

    private final TrustedCaRepository repository;
    private final ApplicationEventPublisher eventPublisher;
    private final CopyOnWriteArrayList<X509Certificate> activeTrustedCas = new CopyOnWriteArrayList<>();

    public TrustedCaService(TrustedCaRepository repository) {
        this(repository, null);
    }

    @Autowired
    public TrustedCaService(TrustedCaRepository repository, ApplicationEventPublisher eventPublisher) {
        this.repository = repository;
        this.eventPublisher = eventPublisher;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        reloadTrustStore();
    }

    public void reloadTrustStore() {
        List<TrustedCaEntity> enabledEntities = repository.findByEnabledTrue();
        List<X509Certificate> loaded = new ArrayList<>();
        for (TrustedCaEntity entity : enabledEntities) {
            try {
                loaded.add(parsePem(entity.getCertificatePem()));
            } catch (Exception e) {
                log.warn("Failed to load Trusted CA '{}' into memory: {}", entity.getAlias(), e.getMessage());
            }
        }
        activeTrustedCas.clear();
        activeTrustedCas.addAll(loaded);
        if (eventPublisher != null) {
            eventPublisher.publishEvent(new TrustedCasReloadedEvent(activeTrustedCas.size()));
        }
        log.info("Hot-reloaded {} active Trusted CA(s) into native TLS truststore (no restart required)", activeTrustedCas.size());
    }

    public List<X509Certificate> getActiveTrustedCas() {
        return List.copyOf(activeTrustedCas);
    }

    @Transactional(readOnly = true)
    public List<TrustedCaDto> listTrustedCas() {
        return repository.findAllByOrderByCreatedAtDesc().stream()
                .map(this::toDto)
                .toList();
    }

    @Transactional
    public TrustedCaDto importTrustedCa(String alias, String certificatePem) {
        if (alias == null || alias.isBlank()) {
            throw new IllegalArgumentException("CA alias is required");
        }
        if (certificatePem == null || certificatePem.isBlank()) {
            throw new IllegalArgumentException("CA certificate PEM is required");
        }
        String normalizedAlias = alias.trim();
        if (repository.existsByAliasIgnoreCase(normalizedAlias)) {
            throw new IllegalArgumentException("Trusted CA with alias '" + normalizedAlias + "' already exists");
        }

        X509Certificate x509 = parsePem(certificatePem);
        if (x509.getBasicConstraints() < 0) {
            throw new IllegalArgumentException("Certificate is not a CA certificate (BasicConstraints CA:TRUE is required)");
        }

        String fingerprint = sha256Hex(x509);
        if (repository.existsByFingerprintSha256(fingerprint)) {
            throw new IllegalArgumentException("This CA certificate is already trusted (fingerprint=" + fingerprint + ")");
        }

        String serialHex = CanonicalizeSerialHexUseCase.toCanonicalSerialHex(x509.getSerialNumber().toString(16));
        TrustedCaEntity entity = TrustedCaEntity.builder()
                .id(UUID.randomUUID().toString())
                .alias(normalizedAlias)
                .subjectDn(x509.getSubjectX500Principal().getName())
                .issuerDn(x509.getIssuerX500Principal().getName())
                .serialNumberHex(serialHex)
                .fingerprintSha256(fingerprint)
                .certificatePem(certificatePem.trim())
                .notBefore(x509.getNotBefore() != null ? x509.getNotBefore().toInstant() : null)
                .notAfter(x509.getNotAfter() != null ? x509.getNotAfter().toInstant() : null)
                .enabled(true)
                .build();

        TrustedCaEntity saved = repository.save(entity);
        reloadTrustStore();
        log.info("Imported and hot-loaded Trusted CA alias='{}' subject='{}'", saved.getAlias(), saved.getSubjectDn());
        return toDto(saved);
    }

    @Transactional
    public TrustedCaDto setEnabled(String id, boolean enabled) {
        TrustedCaEntity entity = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Trusted CA not found: " + id));
        entity.setEnabled(enabled);
        TrustedCaEntity saved = repository.save(entity);
        reloadTrustStore();
        return toDto(saved);
    }

    @Transactional
    public void deleteTrustedCa(String id) {
        TrustedCaEntity entity = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Trusted CA not found: " + id));
        repository.delete(entity);
        reloadTrustStore();
        log.info("Deleted Trusted CA alias='{}' and hot-reloaded truststore", entity.getAlias());
    }

    /**
     * Verifies that {@code clientCert} is cryptographically signed by at least one currently active,
     * non-expired Trusted CA in the hot-reloaded in-memory truststore.
     */
    public boolean isIssuedByTrustedCa(X509Certificate clientCert) {
        if (clientCert == null || activeTrustedCas.isEmpty()) {
            return false;
        }
        Instant now = Instant.now();
        for (X509Certificate ca : activeTrustedCas) {
            if (ca.getNotAfter() != null && now.isAfter(ca.getNotAfter().toInstant())) {
                continue;
            }
            if (ca.getNotBefore() != null && now.isBefore(ca.getNotBefore().toInstant())) {
                continue;
            }
            try {
                clientCert.verify(ca.getPublicKey());
                return true;
            } catch (Exception ignored) {
                // Try next trusted CA
            }
        }
        return false;
    }

    public int activeTrustedCaCount() {
        return activeTrustedCas.size();
    }

    private static X509Certificate parsePem(String pem) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(pem.trim().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid X.509 certificate PEM: " + e.getMessage(), e);
        }
    }

    private static String sha256Hex(X509Certificate cert) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            return HEX.formatHex(digest).toLowerCase();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute SHA-256 fingerprint", e);
        }
    }

    private TrustedCaDto toDto(TrustedCaEntity entity) {
        boolean expired = entity.getNotAfter() != null && Instant.now().isAfter(entity.getNotAfter());
        return new TrustedCaDto(
                entity.getId(),
                entity.getAlias(),
                entity.getSubjectDn(),
                entity.getIssuerDn(),
                entity.getSerialNumberHex(),
                entity.getFingerprintSha256(),
                entity.getNotBefore(),
                entity.getNotAfter(),
                entity.isEnabled(),
                expired,
                entity.getCreatedAt()
        );
    }
}

