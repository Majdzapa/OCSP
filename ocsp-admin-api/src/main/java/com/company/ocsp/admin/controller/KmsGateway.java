package com.company.ocsp.admin.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.List;

/**
 * Thin HTTP client from the admin-api to the KMS service.
 *
 * <p>Used by {@link CertCheckController} to forward signing-cert renewal requests.
 * Kept intentionally simple (RestClient, no mTLS) because this runs on the
 * same trusted internal network as the KMS mock.
 */
@Slf4j
@Service
public class KmsGateway {

    private final RestClient kmsClient;

    public KmsGateway(
            @Value("${kms.base-url:http://localhost:8085}") String kmsBaseUrl) {
        this.kmsClient = RestClient.builder()
                .baseUrl(kmsBaseUrl)
                .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .build();
        log.info("KmsGateway initialised. kms.base-url={}", kmsBaseUrl);
    }

    // -------------------------------------------------------------------------

    public record KmsRenewRequest(String reason) {}

    public record KmsRenewResponse(
        String requestId,
        String status,
        String keyReference,
        String notBefore,
        String notAfter,
        List<String> pemChain
    ) {}

    /**
     * Calls {@code POST /api/v1/kms/ocsp/signing-cert/renew} on the KMS service.
     *
     * @param reason human-readable reason forwarded from the admin console
     * @return KMS response with the new certificate's metadata
     */
    public KmsRenewResponse renewSigningCert(String reason) {
        log.info("Forwarding signing-cert renewal to KMS. reason={}", reason);
        KmsRenewResponse resp = kmsClient.post()
                .uri("/api/v1/kms/ocsp/signing-cert/renew")
                .body(new KmsRenewRequest(reason))
                .retrieve()
                .body(KmsRenewResponse.class);
        log.info("KMS renewal response: status={} notAfter={}", resp.status(), resp.notAfter());
        return resp;
    }
}
