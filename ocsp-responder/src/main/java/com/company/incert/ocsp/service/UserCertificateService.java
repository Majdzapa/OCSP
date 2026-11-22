package com.company.incert.ocsp.service;

import com.company.incert.ocsp.dto.UserCertificateDto;
import com.company.incert.ocsp.entity.RoleEntity;
import com.company.incert.ocsp.entity.UserCertificateEntity;
import com.company.incert.ocsp.entity.UserEntity;
import com.company.incert.ocsp.repository.UserCertificateRepository;
import com.company.incert.ocsp.security.InternalPrincipal;
import com.company.incert.ocsp.usecase.CanonicalizeSerialHexUseCase;
import com.company.incert.ocsp.validation.PatternValidation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Manages X.509 user certificate assignments and optional mTLS client-certificate authentication.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserCertificateService {

    private static final HexFormat HEX = HexFormat.of();

    private final UserCertificateRepository certificateRepository;
    private final UserDomainSupport userDomainSupport;

    @Transactional(readOnly = true)
    public List<UserCertificateDto> listUserCertificates(String userId) {
        userDomainSupport.findActiveById(userId);
        return certificateRepository.findByUserIdOrderByCreatedAtDesc(userId).stream()
                .map(this::toDto)
                .toList();
    }

    @Transactional
    public UserCertificateDto assignCertificate(String userId, String certificatePem) {
        if (certificatePem == null || certificatePem.isBlank()) {
            throw new IllegalArgumentException("Certificate PEM is required");
        }
        UserEntity user = userDomainSupport.findActiveById(userId);
        X509Certificate x509 = parsePem(certificatePem);
        String fingerprint = sha256Hex(x509);
        if (!PatternValidation.isValidSha256Fingerprint(fingerprint)) {
            throw new IllegalStateException("Computed invalid SHA-256 fingerprint");
        }
        if (certificateRepository.existsByFingerprintSha256(fingerprint)) {
            throw new IllegalArgumentException("Certificate is already assigned (fingerprint=" + fingerprint + ")");
        }

        String serialHex = CanonicalizeSerialHexUseCase.toCanonicalSerialHex(x509.getSerialNumber().toString(16));
        UserCertificateEntity entity = UserCertificateEntity.builder()
                .id(UUID.randomUUID().toString())
                .user(user)
                .serialNumberHex(serialHex)
                .fingerprintSha256(fingerprint)
                .subjectDn(x509.getSubjectX500Principal().getName())
                .issuerDn(x509.getIssuerX500Principal().getName())
                .certificatePem(certificatePem.trim())
                .notBefore(x509.getNotBefore() != null ? x509.getNotBefore().toInstant() : null)
                .notAfter(x509.getNotAfter() != null ? x509.getNotAfter().toInstant() : null)
                .revoked(false)
                .build();

        UserCertificateEntity saved = certificateRepository.save(entity);
        log.info("Assigned X.509 certificate id={} serial={} fingerprint={} to user='{}'",
                saved.getId(), saved.getSerialNumberHex(), saved.getFingerprintSha256(), user.getUsername());
        return toDto(saved);
    }

    @Transactional
    public void removeCertificate(String userId, String certId) {
        userDomainSupport.findActiveById(userId);
        UserCertificateEntity cert = certificateRepository.findById(certId)
                .orElseThrow(() -> new IllegalArgumentException("User certificate not found: " + certId));
        if (!cert.getUser().getId().equals(userId)) {
            throw new IllegalArgumentException("Certificate does not belong to user: " + userId);
        }
        certificateRepository.delete(cert);
        log.info("Removed X.509 certificate id={} from userId={}", certId, userId);
    }

    /**
     * Resolves an {@link InternalPrincipal} from a presented mTLS client {@link X509Certificate}.
     */
    @Transactional(readOnly = true)
    public Optional<InternalPrincipal> authenticateByClientCertificate(X509Certificate cert) {
        if (cert == null) {
            return Optional.empty();
        }
        String fingerprint = sha256Hex(cert);
        Instant now = Instant.now();
        return certificateRepository.findActiveWithUserByFingerprint(fingerprint)
                .filter(uc -> uc.getNotBefore() == null || !now.isBefore(uc.getNotBefore()))
                .filter(uc -> uc.getNotAfter() == null || !now.isAfter(uc.getNotAfter()))
                .map(uc -> {
                    UserEntity u = uc.getUser();
                    Set<String> roles = u.getRoles().stream()
                            .map(RoleEntity::getName)
                            .collect(Collectors.toSet());
                    return new InternalPrincipal(
                            u.getId(),
                            u.getUsername(),
                            u.getEmail(),
                            u.getFullName(),
                            u.getTenantId(),
                            u.getAuthSource(),
                            roles
                    );
                });
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
            throw new IllegalStateException("Failed to compute certificate SHA-256 fingerprint", e);
        }
    }

    private UserCertificateDto toDto(UserCertificateEntity entity) {
        return new UserCertificateDto(
                entity.getId(),
                entity.getUser().getId(),
                entity.getSerialNumberHex(),
                entity.getFingerprintSha256(),
                entity.getSubjectDn(),
                entity.getIssuerDn(),
                entity.getNotBefore(),
                entity.getNotAfter(),
                entity.isRevoked(),
                entity.getCreatedAt()
        );
    }
}

