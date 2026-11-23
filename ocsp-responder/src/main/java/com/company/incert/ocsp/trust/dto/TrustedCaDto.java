package com.company.incert.ocsp.trust.dto;

import java.time.Instant;

public record TrustedCaDto(
    String id,
    String alias,
    String subjectDn,
    String issuerDn,
    String serialNumberHex,
    String fingerprintSha256,
    Instant notBefore,
    Instant notAfter,
    boolean enabled,
    boolean expired,
    Instant createdAt
) {}

