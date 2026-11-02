package com.company.kms;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Mock KMS (Key Management Service) — for local development and integration testing only.
 *
 * <p>On startup it:
 * <ul>
 *   <li>Generates an RSA-2048 key pair in memory.</li>
 *   <li>Issues a self-signed X.509 certificate with the {@code id-kp-OCSPSigning} EKU,
 *       simulating a delegated OCSP signing certificate from the CA.</li>
 * </ul>
 *
 * <p>Exposes three HTTP endpoints required by the OCSP subsystem:
 * <ul>
 *   <li>{@code POST /api/v1/kms/sign} — sign arbitrary TBS bytes with the in-memory key.</li>
 *   <li>{@code GET  /api/v1/kms/reconciliation} — return the authoritative revoked cert count.</li>
 *   <li>{@code GET  /api/v1/kms/ocsp/signing-cert/active} — return the signing cert chain.</li>
 * </ul>
 */
@SpringBootApplication
public class KmsApplication {
    public static void main(String[] args) {
        SpringApplication.run(KmsApplication.class, args);
    }
}
