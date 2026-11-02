package com.company.ocsp.admin.service;

import com.company.ocsp.admin.dto.RevocationEventDto;
import com.company.ocsp.admin.model.CertEventAudit;
import com.company.ocsp.admin.repository.CertEventAuditRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.HexFormat;

/**
 * Reads certificate lifecycle events from the {@code cert_event_audit} table
 * and maps them to the DTO exposed by the admin API's revocation feed endpoint.
 *
 * <p>The table is written exclusively by the {@code ocsp-sync-service} on each
 * RabbitMQ message delivery.  The admin API only reads.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RevocationActivityService {

    private final CertEventAuditRepository auditRepository;

    /**
     * Returns a page of recent certificate events ordered by {@code received_at} descending.
     * Page size and number are driven by the caller (typically 25 rows, page 0 from the UI).
     */
    public Page<RevocationEventDto> listRecent(Pageable pageable) {
        return auditRepository
                .findAllByOrderByReceivedAtDesc(pageable)
                .map(this::toDto);
    }

    // -------------------------------------------------------------------------
    // Mapping
    // -------------------------------------------------------------------------

    private RevocationEventDto toDto(CertEventAudit audit) {
        return RevocationEventDto.builder()
                .eventId(audit.getEventId())
                .eventType(audit.getEventType())
                .serialNumberHex(audit.getSerialNumber() != null
                                ? HexFormat.of().formatHex(audit.getSerialNumber()).toUpperCase()
                        : null)
                // revocationReason and revocationTime come from the event payload;
                // they are not stored in cert_event_audit — they live in revocation_status.
                // Return null here; the UI can look them up from the cache if needed.
                .revocationReason(null)
                .revocationTime(null)
                .receivedAt(audit.getReceivedAt())
                .processedAt(audit.getProcessedAt())
                .status(audit.getStatus() != null ? audit.getStatus().name() : null)
                .errorMessage(audit.getErrorMessage())
                .build();
    }
}
