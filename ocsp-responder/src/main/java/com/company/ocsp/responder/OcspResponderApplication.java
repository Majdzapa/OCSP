package com.company.ocsp.responder;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * OCSP Responder — RFC 6960 compliant public certificate status endpoint.
 *
 * <p>Provides:
 * <ul>
 *   <li>POST /ocsp — DER-encoded OCSPRequest body
 *   <li>GET /ocsp/{base64url} — HTTP-cacheable GET variant
 * </ul>
 *
 * <p>Two-layer cache:
 * <ul>
 *   <li>L1: Caffeine (in-JVM, per-instance)
 *   <li>L2: MariaDB {@code ocsp_response_cache} (shared across responder fleet)
 * </ul>
 *
 * <p>Signing is delegated to the KMS via a narrow signing API — no private key
 * material ever enters this service.
 */
@SpringBootApplication
@EnableCaching
@EnableScheduling
public class OcspResponderApplication {

    public static void main(String[] args) {
        SpringApplication.run(OcspResponderApplication.class, args);
    }
}
