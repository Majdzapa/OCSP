package com.company.incert.ocsp.client.dto;

import java.util.List;

/**
 * Result of an OCSP validation performed by the OCSP client.
 */
public record OcspCheckResult(
    boolean valid,
    String responderUrl,
    String method,
    int httpStatus,
    String responseStatus,
    String certStatus,
    String revocationTime,
    String revocationReason,
    String serialHex,
    String thisUpdate,
    String nextUpdate,
    String producedAt,
    String responderId,
    String signerSubject,
    boolean includeNonce,
    String nonceSent,
    String nonceEchoed,
    double latencyMs,
    int requestSizeBytes,
    int responseSizeBytes,
    String getRequestPath,
    List<Check> checks,
    String error
) {
    public enum Outcome { PASS, FAIL, SKIPPED }

    public record Check(String name, Outcome outcome, String detail) {
        public static Check pass(String name, String detail) {
            return new Check(name, Outcome.PASS, detail);
        }

        public static Check fail(String name, String detail) {
            return new Check(name, Outcome.FAIL, detail);
        }

        public static Check skipped(String name, String detail) {
            return new Check(name, Outcome.SKIPPED, detail);
        }
    }
}
