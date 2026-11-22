package com.company.incert.ocsp.auth.dto;

import java.time.Instant;

public record UserCertificateDto(
    String id,
    String userId,
    String serialNumberHex,
    String fingerprintSha256,
    String subjectDn,
    String issuerDn,
    Instant notBefore,
    Instant notAfter,
    boolean revoked,
    Instant createdAt
) {}

