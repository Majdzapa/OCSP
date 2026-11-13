package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.OpenApiConfig;
import com.company.incert.ocsp.entity.InboxEvent;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.repository.InboxEventRepository;
import com.company.incert.ocsp.service.CertificateStatusService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Tag(name = "Inbox & Reconciliation", description = "Endpoints for inspecting RabbitMQ inbox events and verifying synchronization against KMS")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.API_KEY_SCHEME)
public class InboxAdminController {

    private final InboxEventRepository inboxRepository;
    private final CertificateStatusService statusService;
    private final ObjectMapper objectMapper;

    @Value("${kms.url:http://kms-simulator:8090}")
    private String kmsUrl;

    @Operation(summary = "Get inbox events", description = "Retrieves paginated list of certificate status change events received by the responder via RabbitMQ")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Inbox events page returned successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/inbox")
    public ResponseEntity<Map<String, Object>> getInboxEvents(
            @Parameter(description = "Page number (zero-based)", example = "0")
            @RequestParam(value = "page", defaultValue = "0") int page,
            @Parameter(description = "Page size", example = "50")
            @RequestParam(value = "size", defaultValue = "50") int size,
            @Parameter(description = "Filter by certificate serial hex")
            @RequestParam(value = "serial", required = false) String serial) {

        if (serial != null && !serial.isBlank()) {
            List<InboxEvent> list = inboxRepository.findByCertificateSerialOrderByReceivedAtDesc(serial.trim());
            return ResponseEntity.ok(Map.of(
                    "events", list,
                    "total", list.size(),
                    "page", 0,
                    "size", list.size()
            ));
        }

        Page<InboxEvent> paged = inboxRepository.findAllByOrderByReceivedAtDesc(
                PageRequest.of(Math.max(page, 0), Math.min(Math.max(size, 1), 200)));

        return ResponseEntity.ok(Map.of(
                "events", paged.getContent(),
                "total", paged.getTotalElements(),
                "totalPages", paged.getTotalPages(),
                "page", paged.getNumber(),
                "size", paged.getSize()
        ));
    }

    @Operation(summary = "Get inbox processing statistics", description = "Returns aggregated statistics of inbox messages: total received, processed, skipped, duplicates, and errors")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Statistics returned successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/inbox/stats")
    public ResponseEntity<Map<String, Object>> getInboxStats() {
        long total = inboxRepository.count();
        long processed = inboxRepository.countByProcessingStatus("PROCESSED");
        long duplicate = inboxRepository.countByProcessingStatus("DUPLICATE");
        long skipped = inboxRepository.countByProcessingStatus("SKIPPED");
        long failed = inboxRepository.countByProcessingStatus("FAILED");

        return ResponseEntity.ok(Map.of(
                "totalReceived", total,
                "processed", processed,
                "duplicate", duplicate,
                "skipped", skipped,
                "failed", failed
        ));
    }

    @Operation(summary = "Verify synchronization against KMS", description = "Compares all certificates in KMS against the OCSP responder database and inbox to verify 100% receipt and state parity")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Reconciliation report returned successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized"),
        @ApiResponse(responseCode = "502", description = "Failed to communicate with KMS Simulator")
    })
    @GetMapping("/reconciliation/verify")
    public ResponseEntity<?> verifyReconciliation() {
        try {
            RestClient restClient = RestClient.builder().baseUrl(kmsUrl).build();
            String snapshotJson = restClient.get()
                    .uri("/kms/snapshot")
                    .retrieve()
                    .body(String.class);

            List<Map<String, Object>> kmsCerts = objectMapper.readValue(
                    snapshotJson, new TypeReference<List<Map<String, Object>>>() {});

            List<RevocationStatus> responderCerts = statusService.findAll();
            HexFormat hex = HexFormat.of();

            // Index responder certs by normalized serial
            Map<String, RevocationStatus> responderMap = new HashMap<>();
            for (RevocationStatus r : responderCerts) {
                String sHex = hex.formatHex(r.getSerialNumber()).toLowerCase();
                responderMap.put(sHex, r);
            }

            int kmsTotal = kmsCerts.size();
            int responderTotal = responderCerts.size();
            long inboxCount = inboxRepository.count();

            List<String> missingSerials = new ArrayList<>();
            List<Map<String, Object>> mismatches = new ArrayList<>();
            int matched = 0;

            for (Map<String, Object> kc : kmsCerts) {
                String serialHex = String.valueOf(kc.get("serialNumberHex")).toLowerCase();
                String kmsStatus = String.valueOf(kc.get("status"));
                String kmsReason = kc.get("revocationReason") != null ? String.valueOf(kc.get("revocationReason")) : null;

                RevocationStatus rc = responderMap.get(serialHex);
                if (rc == null) {
                    missingSerials.add(serialHex);
                } else {
                    String respStatus = rc.getStatus().name();
                    if (!kmsStatus.equalsIgnoreCase(respStatus)) {
                        mismatches.add(Map.of(
                                "serialNumberHex", serialHex,
                                "kmsStatus", kmsStatus,
                                "responderStatus", respStatus,
                                "subjectDn", kc.getOrDefault("subjectDn", "")
                        ));
                    } else {
                        matched++;
                    }
                }
            }

            boolean isSynchronized = missingSerials.isEmpty() && mismatches.isEmpty() && (kmsTotal == responderTotal);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("synchronized", isSynchronized);
            result.put("kmsTotal", kmsTotal);
            result.put("responderTotal", responderTotal);
            result.put("inboxEventsReceived", inboxCount);
            result.put("matchedCount", matched);
            result.put("missingCount", missingSerials.size());
            result.put("missingSerials", missingSerials);
            result.put("mismatchCount", mismatches.size());
            result.put("statusMismatches", mismatches);
            result.put("verifiedAt", Instant.now().toString());

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Reconciliation verification failed: {}", e.getMessage(), e);
            return ResponseEntity.status(502).body(Map.of(
                    "error", "Failed to connect to KMS Simulator at " + kmsUrl + ": " + e.getMessage()
            ));
        }
    }
}

