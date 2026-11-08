package com.company.incert.ocsp.sync.application.service;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.shared.domain.CertificateStatus;
import com.company.incert.ocsp.shared.domain.RevocationReason;
import com.company.incert.ocsp.status.application.port.in.LookupStatusUseCase;
import com.company.incert.ocsp.sync.application.port.in.ApplyStatusChangeUseCase;
import com.company.incert.ocsp.sync.application.port.in.ReconciliationUseCase;
import com.company.incert.ocsp.sync.domain.StatusChangeCommand;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.*;

@Slf4j
@Service
public class ReconciliationService implements ReconciliationUseCase {

    private final ApplyStatusChangeUseCase applyUseCase;
    private final LookupStatusUseCase lookupUseCase;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;

    @Value("${kms.snapshot.url:http://${KMS_HOST:kms-simulator}:${KMS_PORT:8090}/kms/snapshot}")
    private String kmsSnapshotUrl;

    @Value("${ocsp.reconciliation.enabled:true}")
    private boolean enabled;

    private volatile boolean lastOk = true;
    private volatile Instant lastRunTime;
    private volatile int lastReconciledCount = 0;
    private volatile int lastTotalCount = 0;
    private volatile String lastErrorMessage;

    public ReconciliationService(
            ApplyStatusChangeUseCase applyUseCase,
            LookupStatusUseCase lookupUseCase,
            ObjectMapper objectMapper) {
        this.applyUseCase = applyUseCase;
        this.lookupUseCase = lookupUseCase;
        this.objectMapper = objectMapper;
        this.restTemplate = new RestTemplate();
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onStartup() {
        if (!enabled) return;
        log.info("Triggering initial KMS reconciliation on startup from {}", kmsSnapshotUrl);
        new Thread(() -> {
            try {
                // Wait briefly for KMS to finish initial seeding
                Thread.sleep(3000);
                runReconciliation();
            } catch (Exception e) {
                log.warn("Initial reconciliation attempt failed (will retry via schedule): {}", e.getMessage());
            }
        }, "kms-reconcile-startup").start();
    }

    @Scheduled(cron = "${ocsp.reconciliation.cron:0 0/15 * * * *}")
    public void scheduledReconciliation() {
        if (!enabled) return;
        log.debug("Starting scheduled reconciliation job from {}", kmsSnapshotUrl);
        runReconciliation();
    }

    @Override
    public Map<String, Object> runReconciliation() {
        lastRunTime = Instant.now();
        HexFormat hex = HexFormat.of();
        int reconciled = 0;
        int total = 0;

        try {
            log.info("Fetching certificate snapshot from KMS: {}", kmsSnapshotUrl);
            String json = restTemplate.getForObject(kmsSnapshotUrl, String.class);
            if (json == null || json.isBlank()) {
                throw new IllegalStateException("Empty response from KMS snapshot endpoint");
            }

            List<KmsCertDto> snapshot = objectMapper.readValue(json, new TypeReference<List<KmsCertDto>>() {});
            total = snapshot.size();

            for (KmsCertDto cert : snapshot) {
                try {
                    byte[] nameHash = hex.parseHex(cert.issuerNameHashHex());
                    byte[] keyHash = hex.parseHex(cert.issuerKeyHashHex());
                    byte[] serial = hex.parseHex(cert.serialNumberHex().toLowerCase().replaceAll("[^0-9a-f]", ""));
                    CertId certId = new CertId(nameHash, keyHash, serial);

                    var existing = lookupUseCase.lookup(certId);
                    boolean needsUpdate = existing.isEmpty()
                            || existing.get().sequence() < cert.sequence()
                            || existing.get().status() != cert.status();

                    if (needsUpdate) {
                        RevocationReason reason = cert.revocationReason() != null
                                ? RevocationReason.valueOf(cert.revocationReason())
                                : null;

                        StatusChangeCommand cmd = new StatusChangeCommand(
                                "reconcile-" + cert.serialNumberHex() + "-v" + cert.sequence(),
                                nameHash,
                                keyHash,
                                serial,
                                cert.status(),
                                cert.revocationTime(),
                                reason,
                                Instant.now(),
                                cert.sequence()
                        );
                        applyUseCase.apply(cmd);
                        reconciled++;
                    }
                } catch (Exception certEx) {
                    log.warn("Failed to reconcile certificate {}: {}", cert.serialNumberHex(), certEx.getMessage());
                }
            }

            lastOk = true;
            lastReconciledCount = reconciled;
            lastTotalCount = total;
            lastErrorMessage = null;
            log.info("Reconciliation complete: checked {} certificates, reconciled {} changes", total, reconciled);

            return Map.of(
                    "status", "SUCCESS",
                    "reconciledCount", reconciled,
                    "totalCount", total,
                    "timestamp", lastRunTime.toString()
            );

        } catch (Exception e) {
            lastOk = false;
            lastErrorMessage = e.getMessage();
            log.error("Reconciliation failed: {}", e.getMessage(), e);
            return Map.of(
                    "status", "FAILED",
                    "error", e.getMessage(),
                    "timestamp", lastRunTime.toString()
            );
        }
    }

    @Override
    public boolean isLastReconciliationOk() {
        return lastOk;
    }

    @Override
    public Instant getLastReconciliationTime() {
        return lastRunTime;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record KmsCertDto(
            String serialNumberHex,
            String issuerNameHashHex,
            String issuerKeyHashHex,
            CertificateStatus status,
            Instant revocationTime,
            String revocationReason,
            long sequence
    ) {}
}

