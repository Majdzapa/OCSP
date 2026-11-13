package com.company.incert.kms.domain;

import java.time.Instant;

/**
 * Pure domain record representing a certificate in the KMS inventory.
 * Pure POJO domain model independent of JPA, Spring, or messaging broker.
 */
public record Certificate(
        String serialNumberHex,
        String issuerDn,
        String issuerKeyHashHex,   // hex SHA-1 of issuer public key
        String issuerNameHashHex,  // hex SHA-1 of issuer DN
        String subjectDn,
        Instant notBefore,
        Instant notAfter,
        CertificateStatus status,
        Instant revocationTime,
        RevocationReason revocationReason,
        String pemEncoded,
        long sequence              // monotonic per-certificate sequence number
) {}
