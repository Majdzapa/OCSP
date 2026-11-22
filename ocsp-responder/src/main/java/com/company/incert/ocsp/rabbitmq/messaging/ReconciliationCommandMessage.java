package com.company.incert.ocsp.rabbitmq.messaging;

import java.time.Instant;
import java.util.List;

/**
 * Command message published by OCSP Responder over RabbitMQ to KMS Simulator
 * to request an immediate Outbox manifest or trigger event replay.
 */
public record ReconciliationCommandMessage(
        String command, // "REQUEST_MANIFEST" or "REPLAY_EVENTS"
        Instant requestedAt,
        List<String> missingEventIds,
        List<String> missingSerials
) {}

