package com.company.incert.ocsp.service;

import com.company.incert.ocsp.messaging.CertificateStatusEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Periodically pulls the KMS snapshot to detect and fix any state drift
 * (for example, if RabbitMQ went down or an event was lost).
 */
@Slf4j
@Service
public class ReconciliationService {

    private final CertificateStatusService statusService;
    private final RestClient restClient;
    private final ObjectMapper objectMapper;
    private final String kmsSnapshotUrl;
    private final boolean enabled;

    private volatile boolean lastOk = true;
    private volatile Instant lastRunTime;
    private volatile int lastReconciledCount = 0;
    private volatile int lastTotalCount = 0;

    public ReconciliationService(
            CertificateStatusService statusService,
            RestClient.Builder restClientBuilder,
            ObjectMapper objectMapper,
            @Value("${kms.snapshot.url:http://${KMS_HOST:kms-simulator}:${KMS_PORT:8090}/kms/snapshot}") String kmsSnapshotUrl,
            @Value("${ocsp.reconciliation.enabled:true}") boolean enabled) {
        this.statusService = statusService;
        this.restClient = restClientBuilder.build();
        this.objectMapper = objectMapper;
        this.kmsSnapshotUrl = kmsSnapshotUrl;
        this.enabled = enabled;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onStartup() {
        if (!enabled) return;
        new Thread(() -> {
            try {
                Thread.sleep(3000); // Give the KMS a moment to finish its initial seed
                runReconciliation();
            } catch (Exception e) {
                log.warn("Initial reconciliation attempt failed (will retry via schedule): {}", e.getMessage());
            }
        }, "kms-reconcile-startup").start();
    }

    @Scheduled(cron = "${ocsp.reconciliation.cron:0 0/15 * * * *}")
    public void scheduledReconciliation() {
        if (!enabled) return;
        runReconciliation();
    }

    public synchronized Map<String, Object> runReconciliation() {
        lastRunTime = Instant.now();
        int reconciled = 0;
        int total = 0;
        try {
            log.info("Fetching certificate snapshot from KMS: {}", kmsSnapshotUrl);
            String json = restClient.get().uri(kmsSnapshotUrl).retrieve().body(String.class);
            if (json == null || json.isBlank()) {
                throw new IllegalStateException("Empty response from KMS snapshot endpoint");
            }
            List<CertificateStatusEvent> snapshot = objectMapper.readValue(json, new TypeReference<>() {});
            total = snapshot.size();

            for (CertificateStatusEvent cert : snapshot) {
                try {
                    if (statusService.applyStatusChange(cert)) {
                        reconciled++;
                    }
                } catch (Exception certEx) {
                    log.warn("Failed to reconcile certificate {}: {}", cert.serialNumberHex(), certEx.getMessage());
                }
            }

            lastOk = true;
            lastReconciledCount = reconciled;
            lastTotalCount = total;
            log.info("Reconciliation complete: checked {} certificates, reconciled {} changes", total, reconciled);
            return Map.of(
                "status", "SUCCESS",
                "reconciledCount", reconciled,
                "totalCount", total,
                "timestamp", lastRunTime.toString()
            );
        } catch (Exception e) {
            lastOk = false;
            log.error("Reconciliation failed: {}", e.getMessage(), e);
            return Map.of(
                "status", "FAILED",
                "error", e.getMessage() != null ? e.getMessage() : "Unknown error",
                "timestamp", lastRunTime.toString()
            );
        }
    }

    public boolean isLastReconciliationOk() {
        return lastOk;
    }

    public Instant getLastReconciliationTime() {
        return lastRunTime;
    }

    public int getLastReconciledCount() {
        return lastReconciledCount;
    }

    public int getLastTotalCount() {
        return lastTotalCount;
    }
}
