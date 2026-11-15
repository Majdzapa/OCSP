package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.OpenApiConfig;
import com.company.incert.ocsp.entity.InboxEvent;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.repository.InboxEventRepository;
import com.company.incert.ocsp.service.CertificateStatusService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Tag(name = "Inbox & Reconciliation", description = "Endpoints for inspecting RabbitMQ inbox events and verifying internal inbox-to-status table parity")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.API_KEY_SCHEME)
public class InboxAdminController {

    private final InboxEventRepository inboxRepository;
    private final CertificateStatusService statusService;

    @Operation(summary = "List replicated certificate statuses",
               description = "Returns all certificates replicated into the OCSP responder database via RabbitMQ events")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Replicated certificate statuses returned successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/certificates")
    public ResponseEntity<List<Map<String, Object>>> getCertificates() {
        HexFormat hex = HexFormat.of();
        List<Map<String, Object>> list = statusService.findAll().stream().map(r -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("serialNumberHex", hex.formatHex(r.getSerialNumber()));
            m.put("issuerNameHashHex", hex.formatHex(r.getIssuerNameHash()));
            m.put("issuerKeyHashHex", hex.formatHex(r.getIssuerKeyHash()));
            m.put("status", r.getStatus().name());
            m.put("revocationReason", r.getRevocationReason());
            m.put("revocationTime", r.getRevocationTime() != null ? r.getRevocationTime().toString() : null);
            m.put("thisUpdate", r.getThisUpdate() != null ? r.getThisUpdate().toString() : null);
            m.put("updatedAt", r.getUpdatedAt() != null ? r.getUpdatedAt().toString() : null);
            m.put("sourceEventId", r.getSourceEventId());
            m.put("sequence", r.getSequence());
            return m;
        }).toList();
        return ResponseEntity.ok(list);
    }

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
            List<InboxEvent> list = inboxRepository.findByCertificateSerialContainingIgnoreCaseOrderByReceivedAtDesc(serial.trim());
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

    @Operation(summary = "Verify synchronization between RabbitMQ Inbox and Responder DB",
               description = "Compares the latest RabbitMQ inbox event per certificate serial against the active revocation_status table (purely event-driven, no REST calls to KMS)")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Reconciliation report returned successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/reconciliation/verify")
    public ResponseEntity<Map<String, Object>> verifyReconciliation() {
        List<InboxEvent> allInboxEvents = inboxRepository.findAll();
        List<RevocationStatus> responderCerts = statusService.findAll();
        HexFormat hex = HexFormat.of();

        // Index responder certs by canonical hex serial (minimal two's-complement bytes)
        Map<String, RevocationStatus> responderMap = new HashMap<>();
        for (RevocationStatus r : responderCerts) {
            String sHex = hex.formatHex(
                new java.math.BigInteger(1, r.getSerialNumber()).toByteArray()
            ).toLowerCase();
            responderMap.put(sHex, r);
        }

        // Determine the latest RabbitMQ event per certificate serial by highest sequence (then receivedAt)
        Map<String, InboxEvent> latestInboxBySerial = new LinkedHashMap<>();
        for (InboxEvent ev : allInboxEvents) {
            if ("FAILED".equalsIgnoreCase(ev.getProcessingStatus())) {
                continue;
            }
            String rawSerialHex = String.valueOf(ev.getCertificateSerial()).toLowerCase().replaceAll("[^0-9a-f]", "");
            if (rawSerialHex.isEmpty()) continue;
            if (rawSerialHex.length() % 2 != 0) rawSerialHex = "0" + rawSerialHex;
            String canonicalSerial = hex.formatHex(
                new java.math.BigInteger(1, hex.parseHex(rawSerialHex)).toByteArray()
            ).toLowerCase();

            InboxEvent current = latestInboxBySerial.get(canonicalSerial);
            if (current == null
                    || ev.getSequence() > current.getSequence()
                    || (ev.getSequence() == current.getSequence()
                        && ev.getReceivedAt() != null
                        && (current.getReceivedAt() == null || ev.getReceivedAt().isAfter(current.getReceivedAt())))) {
                latestInboxBySerial.put(canonicalSerial, ev);
            }
        }

        int inboxDistinctTotal = latestInboxBySerial.size();
        int responderTotal = responderCerts.size();
        long inboxCount = allInboxEvents.size();

        List<String> missingSerials = new ArrayList<>();
        List<Map<String, Object>> mismatches = new ArrayList<>();
        int matched = 0;

        for (Map.Entry<String, InboxEvent> entry : latestInboxBySerial.entrySet()) {
            String serialHex = entry.getKey();
            InboxEvent latestEv = entry.getValue();
            String expectedStatus = String.valueOf(latestEv.getStatus());

            RevocationStatus rc = responderMap.get(serialHex);
            if (rc == null) {
                missingSerials.add(serialHex);
            } else {
                String respStatus = rc.getStatus().name();
                if (!expectedStatus.equalsIgnoreCase(respStatus)) {
                    mismatches.add(Map.of(
                            "serialNumberHex", serialHex,
                            "kmsStatus", expectedStatus,
                            "responderStatus", respStatus
                    ));
                } else {
                    matched++;
                }
            }
        }

        boolean isSynchronized = missingSerials.isEmpty() && mismatches.isEmpty();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("synchronized", isSynchronized);
        result.put("kmsTotal", inboxDistinctTotal);
        result.put("responderTotal", responderTotal);
        result.put("inboxEventsReceived", inboxCount);
        result.put("matchedCount", matched);
        result.put("missingCount", missingSerials.size());
        result.put("missingSerials", missingSerials);
        result.put("mismatchCount", mismatches.size());
        result.put("statusMismatches", mismatches);
        result.put("verifiedAt", Instant.now().toString());

        return ResponseEntity.ok(result);
    }
}

