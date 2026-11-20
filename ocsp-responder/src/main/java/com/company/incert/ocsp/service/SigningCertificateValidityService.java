package com.company.incert.ocsp.service;

import com.company.incert.ocsp.dto.GenerateCsrRequest;
import com.company.incert.ocsp.dto.GenerateCsrResponse;
import com.company.incert.ocsp.dto.SigningCertValidityReportDto;
import com.company.incert.ocsp.dto.SigningCertValidityReportDto.CertificateValidityItemDto;
import com.company.incert.ocsp.dto.SigningCertValidityReportDto.ValidityAlertDto;
import com.company.incert.ocsp.entity.SigningCertificate;
import com.company.incert.ocsp.repository.SigningCertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Monitors OCSP signing certificate validity, runs a daily scheduled check, raises alerts
 * when a signing certificate will expire within {@code alertThresholdDays} (default 3 days)
 * or is already expired, and generates PKCS#10 renewal CSRs on demand.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SigningCertificateValidityService {

    private final SigningCertificateRepository repository;
    private final SigningCertificateService signingCertificateService;

    @Value("${ocsp.signing-cert.alert-threshold-days:3}")
    private int alertThresholdDays;

    @Value("${ocsp.signing-cert.validity-cron:0 0 0 * * *}")
    private String dailyCron;

    private final AtomicReference<Instant> lastCheckedAtRef = new AtomicReference<>();

    @EventListener(ApplicationReadyEvent.class)
    @Transactional(readOnly = true)
    public void onStartupCheck() {
        runDailyValidityCheck();
    }

    /**
     * Daily scheduled job (default: every day at 00:00) checking all registered signing certificates
     * and logging alerts for any certificate expiring within 3 days or already expired.
     */
    @Scheduled(cron = "${ocsp.signing-cert.validity-cron:0 0 0 * * *}")
    @Transactional(readOnly = true)
    public SigningCertValidityReportDto runDailyValidityCheck() {
        Instant now = Instant.now();
        lastCheckedAtRef.set(now);
        SigningCertValidityReportDto report = buildReport(now, now);

        if (report.alertActive()) {
            for (ValidityAlertDto alert : report.alerts()) {
                log.warn("[SIGNING-CERT-ALERT] [{}] {}", alert.severity(), alert.message());
            }
        } else {
            log.info("Daily signing certificate validity check completed: total={}, active={}, healthy={}",
                    report.totalCount(), report.activeCount(), report.healthyCount());
        }
        return report;
    }

    @Transactional(readOnly = true)
    public SigningCertValidityReportDto getValidityReport() {
        Instant now = Instant.now();
        Instant lastChecked = lastCheckedAtRef.updateAndGet(prev -> prev != null ? prev : now);
        return buildReport(now, lastChecked);
    }

    /**
     * Creates a PKCS#10 CSR to renew an existing signing certificate, reusing its HSM keypair
     * by default (or generating a new keypair when {@code reuseExistingKey} is false and {@code newKeyLabel} is provided).
     */
    @Transactional(readOnly = true)
    public GenerateCsrResponse createRenewalRequest(Long certificateId, Boolean reuseExistingKey, String newKeyLabel, Integer keySize) {
        SigningCertificate cert = repository.findById(certificateId)
                .orElseThrow(() -> new IllegalArgumentException("Signing certificate not found with id: " + certificateId));

        boolean reuse = reuseExistingKey == null || reuseExistingKey;
        String targetKeyLabel = (!reuse && newKeyLabel != null && !newKeyLabel.isBlank())
                ? newKeyLabel.trim()
                : cert.getKeyLabel();

        String keyAlg = (cert.getSignatureAlgorithm() != null
                && cert.getSignatureAlgorithm().toUpperCase().contains("ECDSA")) ? "EC" : "RSA";
        int resolvedKeySize = keySize != null ? keySize : ("EC".equals(keyAlg) ? 256 : 3072);

        GenerateCsrRequest csrRequest = new GenerateCsrRequest(
                targetKeyLabel,
                cert.getSubjectDn(),
                keyAlg,
                resolvedKeySize,
                reuse
        );

        log.info("Creating renewal CSR for signing certificate id={} alias='{}' keyLabel='{}' reuseKey={}",
                cert.getId(), cert.getAlias(), targetKeyLabel, reuse);
        return signingCertificateService.generateCsr(csrRequest);
    }

    private SigningCertValidityReportDto buildReport(Instant now, Instant lastCheckedAt) {
        int threshold = alertThresholdDays > 0 ? alertThresholdDays : 3;
        List<SigningCertificate> all = repository.findAll();

        List<CertificateValidityItemDto> items = new ArrayList<>(all.size());
        List<ValidityAlertDto> alerts = new ArrayList<>();

        int activeCount = 0;
        int healthyCount = 0;
        int expiringCount = 0;
        int expiredCount = 0;

        for (SigningCertificate cert : all) {
            if (cert.isActive()) {
                activeCount++;
            }

            Instant notAfter = cert.getNotAfter();
            boolean expired = now.isAfter(notAfter);
            Duration remaining = Duration.between(now, notAfter);
            long hoursLeft = remaining.toHours();
            // Ceiling-style or day comparison: if not expired and remaining <= threshold days (e.g. <= 72 hours for 3 days)
            long daysLeft = remaining.toDays();
            boolean expiringWithinThreshold = !expired && remaining.compareTo(Duration.ofDays(threshold)) <= 0;

            String validityStatus;
            if (expired) {
                validityStatus = "EXPIRED";
                expiredCount++;
                String msg = String.format(
                        "Signing certificate '%s' (keyLabel=%s, active=%s) EXPIRED on %s",
                        cert.getAlias(), cert.getKeyLabel(), cert.isActive(), notAfter);
                alerts.add(new ValidityAlertDto(
                        cert.getId(),
                        cert.getAlias(),
                        cert.getKeyLabel(),
                        cert.getSubjectDn(),
                        cert.getIssuerDn(),
                        notAfter,
                        daysLeft,
                        hoursLeft,
                        cert.isActive(),
                        "EXPIRED",
                        msg
                ));
            } else if (expiringWithinThreshold) {
                validityStatus = "EXPIRING_SOON";
                expiringCount++;
                String msg = String.format(
                        "Signing certificate '%s' (keyLabel=%s, active=%s) will expire in %d day(s) (%d hours, notAfter=%s) — threshold is %d days",
                        cert.getAlias(), cert.getKeyLabel(), cert.isActive(), daysLeft, hoursLeft, notAfter, threshold);
                alerts.add(new ValidityAlertDto(
                        cert.getId(),
                        cert.getAlias(),
                        cert.getKeyLabel(),
                        cert.getSubjectDn(),
                        cert.getIssuerDn(),
                        notAfter,
                        daysLeft,
                        hoursLeft,
                        cert.isActive(),
                        "EXPIRING_SOON",
                        msg
                ));
            } else {
                validityStatus = "HEALTHY";
                healthyCount++;
            }

            items.add(new CertificateValidityItemDto(
                    cert.getId(),
                    cert.getAlias(),
                    cert.getKeyLabel(),
                    cert.getSubjectDn(),
                    cert.getIssuerDn(),
                    cert.getSerialNumber(),
                    cert.getSignatureAlgorithm(),
                    cert.getNotBefore(),
                    notAfter,
                    daysLeft,
                    hoursLeft,
                    cert.isActive(),
                    expired,
                    expiringWithinThreshold,
                    validityStatus
            ));
        }

        return new SigningCertValidityReportDto(
                lastCheckedAt,
                threshold,
                dailyCron != null ? dailyCron : "0 0 0 * * *",
                all.size(),
                activeCount,
                healthyCount,
                expiringCount,
                expiredCount,
                !alerts.isEmpty(),
                alerts,
                items
        );
    }
}

