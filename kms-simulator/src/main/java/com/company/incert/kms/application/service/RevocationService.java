package com.company.incert.kms.application.service;

import com.company.incert.kms.application.port.in.ListCertificatesUseCase;
import com.company.incert.kms.application.port.in.RevokeCertificateUseCase;
import com.company.incert.kms.application.port.in.SyncAllCertificatesUseCase;
import com.company.incert.kms.application.port.in.UnrevokeCertificateUseCase;
import com.company.incert.kms.application.port.in.UpdateCertificateStatusUseCase;
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
 * Core revocation and certificate lifecycle service implementation.
 * Depends only on domain and port interfaces — decoupled from infrastructure.
 */
@Slf4j
@RequiredArgsConstructor
public class RevocationService
        implements RevokeCertificateUseCase, UnrevokeCertificateUseCase,
                   ListCertificatesUseCase, UpdateCertificateStatusUseCase,
                   SyncAllCertificatesUseCase {

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
    @Transactional
    public Certificate updateStatus(String serialHex, CertificateStatus targetStatus, RevocationReason reason, Instant revocationTime) {
        Certificate cert = certRepository.findBySerial(serialHex)
                .orElseThrow(() -> new CertificateNotFoundException("Certificate not found: " + serialHex));

        Instant finalRevTime = null;
        RevocationReason finalReason = null;

        if (targetStatus == CertificateStatus.REVOKED) {
            finalRevTime = revocationTime != null ? revocationTime : Instant.now();
            finalReason = reason != null ? reason : RevocationReason.UNSPECIFIED;
        }

        Certificate updated = new Certificate(
                cert.serialNumberHex(), cert.issuerDn(), cert.issuerKeyHashHex(),
                cert.issuerNameHashHex(), cert.subjectDn(), cert.notBefore(), cert.notAfter(),
                targetStatus, finalRevTime, finalReason, cert.pemEncoded(),
                cert.sequence() + 1
        );

        Certificate saved = certRepository.save(updated);
        outboxWriter.write(CertificateStatusChangedEvent.from(saved));
        log.info("Updated certificate status serial={} status={} reason={} seq={}",
                serialHex, targetStatus, finalReason, saved.sequence());
        return saved;
    }

    @Override
    @Transactional
    public int syncAll() {
        List<Certificate> all = certRepository.findAll();
        for (Certificate cert : all) {
            outboxWriter.write(CertificateStatusChangedEvent.from(cert));
        }
        log.info("Queued outbox sync events for all {} certificates in KMS", all.size());
        return all.size();
    }

    @Override
    public List<Certificate> listAll() {
        return certRepository.findAll();
    }

    public static class CertificateNotFoundException extends RuntimeException {
        public CertificateNotFoundException(String msg) { super(msg); }
    }
}
