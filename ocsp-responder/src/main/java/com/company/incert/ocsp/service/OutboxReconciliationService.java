package com.company.incert.ocsp.service;

import com.company.incert.ocsp.config.OcspRabbitMqProperties;
import com.company.incert.ocsp.entity.InboxEvent;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.messaging.OutboxManifestEvent;
import com.company.incert.ocsp.messaging.ReconciliationCommandMessage;
import com.company.incert.ocsp.repository.InboxEventRepository;
import com.company.incert.ocsp.usecase.CanonicalizeSerialHexUseCase;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Purely event-driven Outbox <-> Inbox reconciliation service.
 * <p>
 * Consumes {@link OutboxManifestEvent} messages broadcast by KMS over RabbitMQ and compares
 * KMS Outbox event IDs and certificate digests against {@code ocsp.inbox_event} and
 * {@code ocsp.revocation_status} without making any HTTP/REST call to KMS.
 * When missing, failed, or stale events are found, can publish a {@link ReconciliationCommandMessage}
 * over RabbitMQ asking KMS to replay them.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OutboxReconciliationService {

    private final InboxEventRepository inboxRepository;
    private final CertificateStatusService statusService;
    private final RabbitTemplate rabbitTemplate;
    private final ObjectMapper objectMapper;
    private final OcspRabbitMqProperties rabbitProperties;

    private final AtomicReference<OutboxManifestEvent> latestManifestRef = new AtomicReference<>();

    @RabbitListener(queues = "${ocsp.rabbitmq.reconciliation-manifest-queue}")
    public void onOutboxManifest(String payload) {
        try {
            OutboxManifestEvent manifest = objectMapper.readValue(payload, OutboxManifestEvent.class);
            latestManifestRef.set(manifest);
            log.debug("Received KMS Outbox manifest via RabbitMQ: id={} certs={} outboxEvents={}",
                    manifest.manifestId(), manifest.totalCertificates(), manifest.totalOutboxEvents());
        } catch (Exception e) {
            log.warn("Failed to parse OutboxManifestEvent from RabbitMQ: {}", e.getMessage());
        }
    }

    public OutboxManifestEvent getLatestManifest() {
        return latestManifestRef.get();
    }

    public void requestManifestViaRabbitMq() {
        publishCommand(new ReconciliationCommandMessage("REQUEST_MANIFEST", Instant.now(), List.of(), List.of()));
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> triggerReplayViaRabbitMq() {
        Map<String, Object> report = verifyReconciliation();
        List<String> missingInInbox = (List<String>) report.getOrDefault("missingInInboxEventIds", List.of());
        List<String> failedInInbox = (List<String>) report.getOrDefault("failedInInboxEventIds", List.of());
        List<String> missingSerials = (List<String>) report.getOrDefault("missingSerials", List.of());
        List<Map<String, Object>> mismatches = (List<Map<String, Object>>) report.getOrDefault("statusMismatches", List.of());

        Set<String> eventIdsToReplay = new LinkedHashSet<>();
        eventIdsToReplay.addAll(missingInInbox);
        eventIdsToReplay.addAll(failedInInbox);

        Set<String> serialsToReplay = new LinkedHashSet<>(missingSerials);
        for (Map<String, Object> m : mismatches) {
            Object s = m.get("serialNumberHex");
            if (s != null) {
                serialsToReplay.add(s.toString());
            }
        }

        ReconciliationCommandMessage cmd = new ReconciliationCommandMessage(
                "REPLAY_EVENTS",
                Instant.now(),
                List.copyOf(eventIdsToReplay),
                List.copyOf(serialsToReplay)
        );
        publishCommand(cmd);

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("status", "REPLAY_REQUESTED_VIA_RABBITMQ");
        res.put("requestedEventIds", eventIdsToReplay);
        res.put("requestedSerials", serialsToReplay);
        res.put("requestedAt", cmd.requestedAt().toString());
        return res;
    }

    private void publishCommand(ReconciliationCommandMessage cmd) {
        try {
            String json = objectMapper.writeValueAsString(cmd);
            MessageProperties props = new MessageProperties();
            props.setContentType(MessageProperties.CONTENT_TYPE_JSON);
            props.setContentEncoding(StandardCharsets.UTF_8.name());
            props.setMessageId(UUID.randomUUID().toString());
            rabbitTemplate.send(rabbitProperties.getExchange(), rabbitProperties.getReconciliationRequestRoutingKey(),
                    new Message(json.getBytes(StandardCharsets.UTF_8), props));
        } catch (Exception e) {
            log.warn("Could not publish reconciliation command {} to RabbitMQ: {}", cmd.command(), e.getMessage());
        }
    }

    public Map<String, Object> verifyReconciliation() {
        OutboxManifestEvent manifest = latestManifestRef.get();
        if (manifest == null) {
            requestManifestViaRabbitMq();
        }

        List<InboxEvent> allInboxEvents = inboxRepository.findAll();
        List<RevocationStatus> responderCerts = statusService.findAll();
        HexFormat hex = HexFormat.of();

        Map<String, RevocationStatus> responderMap = new HashMap<>();
        for (RevocationStatus r : responderCerts) {
            String sHex = canonicalHex(hex.formatHex(r.getSerialNumber()), hex);
            if (!sHex.isEmpty()) {
                responderMap.put(sHex, r);
            }
        }

        Map<String, InboxEvent> inboxByEventId = new HashMap<>();
        List<String> failedInInboxEventIds = new ArrayList<>();
        Map<String, InboxEvent> latestInboxBySerial = new LinkedHashMap<>();

        for (InboxEvent ev : allInboxEvents) {
            inboxByEventId.put(ev.getEventId(), ev);
            if ("FAILED".equalsIgnoreCase(ev.getProcessingStatus())) {
                failedInInboxEventIds.add(ev.getEventId());
                continue;
            }
            String canonicalSerial = canonicalHex(ev.getCertificateSerial(), hex);
            if (canonicalSerial.isEmpty()) continue;

            InboxEvent current = latestInboxBySerial.get(canonicalSerial);
            if (current == null
                    || ev.getSequence() > current.getSequence()
                    || (ev.getSequence() == current.getSequence()
                        && ev.getReceivedAt() != null
                        && (current.getReceivedAt() == null || ev.getReceivedAt().isAfter(current.getReceivedAt())))) {
                latestInboxBySerial.put(canonicalSerial, ev);
            }
        }

        List<String> missingInInboxEventIds = new ArrayList<>();
        if (manifest != null && manifest.outboxEventIds() != null) {
            for (String outboxEventId : manifest.outboxEventIds()) {
                if (!inboxByEventId.containsKey(outboxEventId)) {
                    missingInInboxEventIds.add(outboxEventId);
                }
            }
        }

        List<String> missingSerials = new ArrayList<>();
        List<Map<String, Object>> mismatches = new ArrayList<>();
        int matched = 0;

        if (manifest != null && manifest.certificates() != null) {
            // Compare directly against the KMS Outbox manifest received via RabbitMQ
            for (OutboxManifestEvent.CertificateDigest cert : manifest.certificates()) {
                String serialHex = canonicalHex(cert.serialNumberHex(), hex);
                if (serialHex.isEmpty()) continue;

                String expectedStatus = String.valueOf(cert.status());
                RevocationStatus rc = responderMap.get(serialHex);
                if (rc == null) {
                    missingSerials.add(serialHex);
                } else {
                    String respStatus = rc.getStatus().name();
                    if (!expectedStatus.equalsIgnoreCase(respStatus) || rc.getSequence() < cert.sequence()) {
                        Map<String, Object> mismatch = new LinkedHashMap<>();
                        mismatch.put("serialNumberHex", serialHex);
                        mismatch.put("kmsStatus", expectedStatus);
                        mismatch.put("responderStatus", respStatus);
                        mismatch.put("kmsSequence", cert.sequence());
                        mismatch.put("responderSequence", rc.getSequence());
                        mismatches.add(mismatch);
                    } else {
                        matched++;
                    }
                }
            }
        } else {
            // Fallback to Inbox vs Responder DB until the first RabbitMQ Outbox manifest arrives
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
        }

        long outboxTotalEvents = manifest != null ? manifest.totalOutboxEvents() : allInboxEvents.size();
        long outboxSentEvents = manifest != null ? manifest.sentOutboxEvents() : allInboxEvents.size();
        long outboxPendingEvents = manifest != null ? manifest.pendingOutboxEvents() : 0L;
        int kmsTotal = manifest != null ? manifest.totalCertificates() : latestInboxBySerial.size();
        int responderTotal = responderCerts.size();
        long inboxCount = allInboxEvents.size();

        boolean isSynchronized = missingSerials.isEmpty()
                && mismatches.isEmpty()
                && missingInInboxEventIds.isEmpty()
                && failedInInboxEventIds.isEmpty()
                && outboxPendingEvents == 0;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("synchronized", isSynchronized);
        result.put("manifestReceived", manifest != null);
        result.put("manifestGeneratedAt", manifest != null && manifest.generatedAt() != null ? manifest.generatedAt().toString() : null);
        result.put("outboxTotalEvents", outboxTotalEvents);
        result.put("outboxSentEvents", outboxSentEvents);
        result.put("outboxPendingEvents", outboxPendingEvents);
        result.put("missingInInboxCount", missingInInboxEventIds.size());
        result.put("missingInInboxEventIds", missingInInboxEventIds);
        result.put("failedInInboxCount", failedInInboxEventIds.size());
        result.put("failedInInboxEventIds", failedInInboxEventIds);
        result.put("kmsTotal", kmsTotal);
        result.put("responderTotal", responderTotal);
        result.put("inboxEventsReceived", inboxCount);
        result.put("matchedCount", matched);
        result.put("missingCount", missingSerials.size());
        result.put("missingSerials", missingSerials);
        result.put("mismatchCount", mismatches.size());
        result.put("statusMismatches", mismatches);
        result.put("verifiedAt", Instant.now().toString());
        return result;
    }

    private static String canonicalHex(String rawSerial, HexFormat hex) {
        return CanonicalizeSerialHexUseCase.toCanonicalSerialHex(rawSerial);
    }
}

