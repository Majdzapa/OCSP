package com.company.incert.kms.service;

import com.company.incert.kms.entity.Certificate;
import com.company.incert.kms.entity.CertificateStatus;
import com.company.incert.kms.entity.RevocationReason;
import com.company.incert.kms.repository.CertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Random;

/**
 * Scheduled job that periodically revokes or unrevokes random certificates to simulate KMS activity.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RevocationJob {

    private final RevocationService revocationService;
    private final CertificateRepository certRepository;

    @Value("${kms.job.revocation.enabled:true}")
    private boolean enabled;

    @Value("${kms.job.revocation.seed:-1}")
    private long seed;

    private static final RevocationReason[] REASONS = {
        RevocationReason.KEY_COMPROMISE, RevocationReason.AFFILIATION_CHANGED,
        RevocationReason.SUPERSEDED, RevocationReason.CESSATION_OF_OPERATION,
        RevocationReason.CERTIFICATE_HOLD
    };

    @Scheduled(cron = "${kms.job.revocation.cron:0/30 * * * * *}")
    public void run() {
        if (!enabled) return;
        log.debug("Revocation job triggered");
        try {
            runInternal();
        } catch (Exception e) {
            log.error("Revocation job failed: {}", e.getMessage(), e);
        }
    }

    /** Programmatic trigger for the REST dev endpoint. */
    public void runNow() {
        log.info("Manual revocation job trigger");
        runInternal();
    }

    private void runInternal() {
        Random rng = (seed >= 0) ? new Random(seed) : new Random();
        List<Certificate> certs = certRepository.findAll();
        if (certs.isEmpty()) {
            log.warn("No certificates found in KMS database");
            return;
        }

        // Pick a random cert
        Certificate target = certs.get(rng.nextInt(certs.size()));

        if (target.getStatus() == CertificateStatus.GOOD) {
            // Revoke with random reason
            RevocationReason reason = REASONS[rng.nextInt(REASONS.length)];
            revocationService.revoke(target.getSerialNumberHex(), reason);
            log.info("Job: Revoked cert serial={} reason={}", target.getSerialNumberHex(), reason);
        } else if (target.getStatus() == CertificateStatus.REVOKED
                && target.getRevocationReason() == RevocationReason.CERTIFICATE_HOLD) {
            // If on hold, unrevoke
            revocationService.unrevoke(target.getSerialNumberHex());
            log.info("Job: Unrevoked cert serial={}", target.getSerialNumberHex());
        } else {
            // Already revoked with a permanent reason — pick a GOOD cert to revoke instead
            certs.stream()
                    .filter(c -> c.getStatus() == CertificateStatus.GOOD)
                    .findAny()
                    .ifPresent(goodCert -> {
                        RevocationReason reason = REASONS[rng.nextInt(REASONS.length)];
                        revocationService.revoke(goodCert.getSerialNumberHex(), reason);
                        log.info("Job: Revoked alternate cert serial={} reason={}", goodCert.getSerialNumberHex(), reason);
                    });
        }
    }
}
