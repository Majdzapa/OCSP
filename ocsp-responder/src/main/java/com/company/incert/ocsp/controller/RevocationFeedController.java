package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.OpenApiConfig;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.service.CertificateStatusService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Tag(name = "Revocations", description = "Endpoints for inspecting revoked certificates and event synchronization feeds")
@SecurityRequirement(name = OpenApiConfig.BASIC_AUTH_SCHEME)
@SecurityRequirement(name = OpenApiConfig.API_KEY_SCHEME)
public class RevocationFeedController {

    private final CertificateStatusService statusService;

    @Operation(summary = "Get paginated revocation feed", description = "Retrieves paginated list of revoked certificates received from RabbitMQ and stored in MariaDB")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Revocation feed page returned successfully"),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping({"/revocations", "/revocation-feed"})
    public ResponseEntity<Map<String, Object>> getRevoked(
            @Parameter(description = "Page number (zero-based)", example = "0")
            @RequestParam(value = "page", defaultValue = "0") int page,
            @Parameter(description = "Page size", example = "50")
            @RequestParam(value = "size", defaultValue = "50") int size) {
        Page<RevocationStatus> paged = statusService.findRevoked(page, size);
        HexFormat hex = HexFormat.of();
        List<Map<String, String>> content = paged.getContent().stream().map(e -> {
            String serialHex = hex.formatHex(e.getSerialNumber());
            String eventId = e.getSourceEventId() != null ? e.getSourceEventId() : "evt-" + e.getId();
            String revTime = e.getRevocationTime() != null ? e.getRevocationTime().toString() : "";
            String revReason = e.getRevocationReason() != null ? e.getRevocationReason() : "UNSPECIFIED";
            String recAt = e.getUpdatedAt() != null ? e.getUpdatedAt().toString() : e.getThisUpdate().toString();
            Map<String, String> map = new HashMap<>();
            map.put("eventId", eventId);
            map.put("eventType", "CertificateRevoked");
            map.put("serialNumberHex", serialHex);
            map.put("serialNumber", serialHex);
            map.put("issuerKeyHash", hex.formatHex(e.getIssuerKeyHash()));
            map.put("revocationTime", revTime);
            map.put("revocationReason", revReason);
            map.put("receivedAt", recAt);
            map.put("processedAt", recAt);
            map.put("status", "PROCESSED");
            map.put("thisUpdate", e.getThisUpdate().toString());
            return map;
        }).toList();

        return ResponseEntity.ok(Map.of(
            "content", content,
            "totalElements", paged.getTotalElements(),
            "totalPages", paged.getTotalPages(),
            "number", page,
            "size", size
        ));
    }
}

