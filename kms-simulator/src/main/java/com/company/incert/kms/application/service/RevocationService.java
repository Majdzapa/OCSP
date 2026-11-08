package com.company.incert.kms.application.service;

import com.company.incert.kms.application.port.in.ListCertificatesUseCase;
import com.company.incert.kms.application.port.in.RevokeCertificateUseCase;
import com.company.incert.kms.application.port.in.UnrevokeCertificateUseCase;
import com.company.incert.kms.application.port.out.CertificateRepository;
import com.company.incert.kms.application.port.out.OutboxWriter;
import com.company.incert.kms.domain.Certificate;
import com.company.incert.kms.domain.CertificateStatus;
import com.company.incert.kms.domain.CertificateStatusChangedEvent;
import com.company.incert.kms.domain.RevocationReason;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Core revocation use-case implementation.
 * Depends only on domain and port interfaces — no adapters here.
 */
@Slf4j
@RequiredArgsConstructor
public class RevocationService
        implements RevokeCertificateUseCase, UnrevokeCertificateUseCase, ListCertificatesUseCase {

    private final CertificateRepository certRepository;
    private final OutboxWriter outboxWriter;

    @Override
    @Transactional
    public Certificate revoke(String serialHex, RevocationReason reason) {
        Certificate cert = certRepository.findBySerial(serialHex)
                .orElseThrow(() -> new CertificateNotFoundException("Certificate not found: " + serialHex));
        if (cert.status() == CertificateStatus.REVOKED) {
            log.warn("Certificate {} already revoked, skipping", serialHex);
            return cert;
        }
        Certificate updated = new Certificate(
                cert.serialNumberHex(), cert.issuerDn(), cert.issuerKeyHashHex(),
                cert.issuerNameHashHex(), cert.subjectDn(), cert.notBefore(), cert.notAfter(),
                CertificateStatus.REVOKED, Instant.now(), reason, cert.pemEncoded(),
                cert.sequence() + 1
        );
        Certificate saved = certRepository.save(updated);
        outboxWriter.write(CertificateStatusChangedEvent.from(saved));
        log.info("Revoked certificate serial={} reason={}", serialHex, reason);
        return saved;
    }

    @Override
    @Transactional
    public Certificate unrevoke(String serialHex) {
        Certificate cert = certRepository.findBySerial(serialHex)
                .orElseThrow(() -> new CertificateNotFoundException("Certificate not found: " + serialHex));
        if (cert.revocationReason() != RevocationReason.CERTIFICATE_HOLD) {
            throw new IllegalStateException(
                    "Can only unrevoke CERTIFICATE_HOLD, current reason: " + cert.revocationReason());
        }
        Certificate updated = new Certificate(
                cert.serialNumberHex(), cert.issuerDn(), cert.issuerKeyHashHex(),
                cert.issuerNameHashHex(), cert.subjectDn(), cert.notBefore(), cert.notAfter(),
                CertificateStatus.GOOD, null, null, cert.pemEncoded(),
                cert.sequence() + 1
        );
        Certificate saved = certRepository.save(updated);
        outboxWriter.write(CertificateStatusChangedEvent.from(saved));
        log.info("Unrevoked certificate serial={}", serialHex);
        return saved;
    }

    @Override
    public List<Certificate> listAll() {
        return certRepository.findAll();
    }

    public static class CertificateNotFoundException extends RuntimeException {
        public CertificateNotFoundException(String msg) { super(msg); }
    }
}
