package com.company.incert.ocsp.controller;

import com.company.incert.ocsp.config.KeycloakProperties;
import com.company.incert.ocsp.service.KeycloakSyncService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Internal webhook receiver for Keycloak Admin Events ({@code CREATE}, {@code UPDATE}, {@code DELETE}, {@code DISABLE}).
 * Secured by shared secret header {@code X-Webhook-Secret} configured in {@code keycloak.webhook-secret}.
 */
@RestController
@RequestMapping("/api/v1/internal/keycloak")
@RequiredArgsConstructor
@Tag(name = "Keycloak Sync Webhook", description = "Idempotent Keycloak Admin Event webhook receiver")
public class KeycloakWebhookController {

    private final KeycloakSyncService syncService;
    private final KeycloakProperties keycloakProperties;

    public record KeycloakEventPayload(
        String eventType,
        String externalId,
        String username,
        String email,
        Boolean emailVerified,
        String fullName,
        Boolean enabled
    ) {}

    @Operation(summary = "Receive Keycloak user lifecycle event", description = "Idempotently upserts, disables, or soft-deletes the DB replica keyed by external_id")
    @PostMapping("/events")
    public ResponseEntity<Map<String, Object>> onEvent(
            @RequestHeader(value = "X-Webhook-Secret", required = false) String providedSecret,
            @RequestBody KeycloakEventPayload payload) {

        String expected = keycloakProperties.getWebhookSecret();
        if (expected == null || expected.isBlank() || providedSecret == null
                || !MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), providedSecret.getBytes(StandardCharsets.UTF_8))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid webhook secret"));
        }

        syncService.handleWebhookEvent(
                payload.eventType(),
                payload.externalId(),
                payload.username(),
                payload.email(),
                payload.emailVerified(),
                payload.fullName(),
                payload.enabled()
        );
        return ResponseEntity.ok(Map.of("status", "SYNCED", "externalId", String.valueOf(payload.externalId())));
    }
}

