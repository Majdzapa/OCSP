package com.company.incert.ocsp.service;

import com.company.incert.ocsp.config.ScheduledJobsProperties;
import com.company.incert.ocsp.entity.IdentityOutboxEntity;
import com.company.incert.ocsp.repository.IdentityOutboxRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Outbox &amp; retry helper for non-transactional Keycloak Admin API calls.
 * Avoids 2PC/distributed transactions by persisting failed operations and retrying them
 * in {@link com.company.incert.ocsp.config.ScheduledJobsConfig}.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IdentityOutboxService {

    private final IdentityOutboxRepository outboxRepository;
    private final KeycloakAdminClient keycloakAdminClient;
    private final ScheduledJobsProperties jobsProperties;
    private final ObjectMapper objectMapper;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordPending(String userId, String operation, Map<String, Object> payloadMap, String error) {
        try {
            String json = objectMapper.writeValueAsString(payloadMap);
            IdentityOutboxEntity entity = IdentityOutboxEntity.builder()
                    .id(UUID.randomUUID().toString())
                    .userId(userId)
                    .operation(operation)
                    .payload(json)
                    .attempts(0)
                    .lastError(error != null && error.length() > 950 ? error.substring(0, 950) : error)
                    .processed(false)
                    .build();
            outboxRepository.save(entity);
            log.warn("Recorded identity_outbox retry entry: userId={} op={} err={}", userId, operation, error);
        } catch (Exception e) {
            log.error("Failed to persist identity_outbox entry for userId={}: {}", userId, e.getMessage());
        }
    }

    @Transactional
    @SuppressWarnings("unchecked")
    public int retryPending() {
        int maxAttempts = Math.max(1, jobsProperties.getIdentityOutboxRetry().getMaxAttempts());
        List<IdentityOutboxEntity> pending = outboxRepository.findTop50ByProcessedFalseOrderByCreatedAtAsc();
        int succeeded = 0;

        for (IdentityOutboxEntity entry : pending) {
            if (entry.getAttempts() >= maxAttempts) {
                continue;
            }
            try {
                Map<String, Object> map = objectMapper.readValue(entry.getPayload(), Map.class);
                String externalId = (String) map.get("externalId");
                switch (entry.getOperation()) {
                    case "UPDATE" -> keycloakAdminClient.updateUser(
                            externalId,
                            (String) map.get("email"),
                            (String) map.get("fullName"),
                            (Boolean) map.get("enabled"));
                    case "SET_ENABLED" -> keycloakAdminClient.updateUser(
                            externalId, null, null, (Boolean) map.get("enabled"));
                    case "DELETE" -> keycloakAdminClient.deleteUser(externalId);
                    case "RESET_PASSWORD" -> keycloakAdminClient.sendResetPasswordEmail(externalId);
                    default -> log.debug("Skipping unknown identity_outbox operation {}", entry.getOperation());
                }
                entry.setProcessed(true);
                entry.setLastError(null);
                succeeded++;
            } catch (Exception e) {
                entry.setAttempts(entry.getAttempts() + 1);
                String msg = e.getMessage();
                entry.setLastError(msg != null && msg.length() > 950 ? msg.substring(0, 950) : msg);
                log.warn("Identity outbox retry failed (attempt {}/{}) id={}: {}",
                        entry.getAttempts(), maxAttempts, entry.getId(), msg);
            }
            outboxRepository.save(entry);
        }
        return succeeded;
    }
}

