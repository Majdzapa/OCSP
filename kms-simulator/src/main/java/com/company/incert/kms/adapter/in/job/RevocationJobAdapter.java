package com.company.incert.kms.adapter.in.job;

import com.company.incert.kms.application.port.in.RevokeCertificateUseCase;
import com.company.incert.kms.application.port.in.UnrevokeCertificateUseCase;
import com.company.incert.kms.application.port.out.CertificateRepository;
import com.company.incert.kms.domain.Certificate;
import com.company.incert.kms.domain.CertificateStatus;
import com.company.incert.kms.domain.RevocationReason;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Random;

/**
 * Scheduled job that randomly revokes/unrevokes certificates to simulate KMS activity.
 * Configurable via kms.job.revocation.enabled and kms.job.revocation.cron.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RevocationJobAdapter {

    private final RevokeCertificateUseCase revokeUseCase;
    private final UnrevokeCertificateUseCase unrevokeUseCase;
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
        Random rng = seed < 0 ? new Random() : new Random(seed);
        List<Certificate> allCerts = certRepository.findAll();
        if (allCerts.isEmpty()) return;

        // Revoke 1-3 GOOD certs
        List<Certificate> goodCerts = allCerts.stream()
                .filter(c -> c.status() == CertificateStatus.GOOD)
                .toList();
        int revokeCount = Math.min(1 + rng.nextInt(3), goodCerts.size());
        for (int i = 0; i < revokeCount; i++) {
            Certificate target = goodCerts.get(rng.nextInt(goodCerts.size()));
            RevocationReason reason = REASONS[rng.nextInt(REASONS.length)];
            try {
                revokeUseCase.revoke(target.serialNumberHex(), reason);
            } catch (Exception e) {
                log.warn("Could not revoke {}: {}", target.serialNumberHex(), e.getMessage());
            }
        }

        // Unrevoke 0-1 CERTIFICATE_HOLD certs
        List<Certificate> holdCerts = allCerts.stream()
                .filter(c -> c.status() == CertificateStatus.REVOKED
                        && c.revocationReason() == RevocationReason.CERTIFICATE_HOLD)
                .toList();
        if (!holdCerts.isEmpty() && rng.nextBoolean()) {
            Certificate target = holdCerts.get(rng.nextInt(holdCerts.size()));
            try {
                unrevokeUseCase.unrevoke(target.serialNumberHex());
            } catch (Exception e) {
                log.warn("Could not unrevoke {}: {}", target.serialNumberHex(), e.getMessage());
            }
        }
    }
}
