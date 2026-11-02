package com.company.ocsp.responder.messaging;

import com.company.ocsp.responder.cache.OcspResponseCacheManager;
import com.company.ocsp.responder.util.CertIdCacheKeyUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;
import org.bouncycastle.util.encoders.Hex;

import java.util.Map;

/**
 * Listens for {@code StatusChanged} cache-invalidation signals published by the
 * {@code ocsp-sync-service} after it has committed a revocation status update to
 * MariaDB.
 *
 * <p>On receipt, the responder proactively evicts the stale cached response for
 * the affected certificate from both L1 (Caffeine) and L2 (MariaDB
 * {@code ocsp_response_cache}), so the next request for that certificate will
 * trigger a fresh response — satisfying the &lt;60 second revocation propagation SLA.
 *
 * <p>Without this listener, cache entries would linger until their {@code nextUpdate}
 * (up to 1 hour), delaying revocation visibility.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CacheInvalidationListener {

    private final OcspResponseCacheManager cacheManager;

    /**
     * Handles a {@code StatusChanged} message from the
     * {@code ocsp.cache.invalidate} queue.
     *
     * <p>Message payload (JSON map) is expected to carry:
     * <ul>
     *   <li>{@code issuerNameHashHex} — hex-encoded SHA-1 of issuer DN
     *   <li>{@code issuerKeyHashHex}  — hex-encoded SHA-1 of issuer public key
     *   <li>{@code serialNumberHex}   — hex-encoded certificate serial number
     * </ul>
     */
    @RabbitListener(queues = "${ocsp.rabbitmq.cache-invalidation-queue}")
    public void onStatusChanged(Map<String, String> payload) {
        try {
            byte[] issuerNameHash = Hex.decode(payload.get("issuerNameHashHex"));
            byte[] issuerKeyHash  = Hex.decode(payload.get("issuerKeyHashHex"));
            byte[] serialNumber   = Hex.decode(payload.get("serialNumberHex"));

            String cacheKey = CertIdCacheKeyUtil.computeKey(issuerNameHash, issuerKeyHash, serialNumber);
            log.info("Received cache-invalidation signal for cacheKey={}", cacheKey);
            cacheManager.evict(cacheKey);
        } catch (Exception e) {
            log.error("Failed to process cache-invalidation message: payload={}", payload, e);
            // Do not re-throw: a failed eviction is not fatal — the entry will
            // expire naturally at nextUpdate.  Alerting is via metrics/logs.
        }
    }
}
