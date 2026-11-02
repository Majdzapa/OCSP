package com.company.ocsp.admin.dto;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class RevocationEventDto {
    private String  eventId;
    private String  eventType;
    private String  serialNumberHex;
    private String  revocationReason;
    private Instant revocationTime;
    private Instant receivedAt;
    private Instant processedAt;
    private String  status;   // RECEIVED | PROCESSED | FAILED
    private String  errorMessage;
}
