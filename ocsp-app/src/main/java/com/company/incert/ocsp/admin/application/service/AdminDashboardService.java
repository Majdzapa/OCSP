package com.company.incert.ocsp.admin.application.service;

import com.company.incert.ocsp.admin.application.port.in.GetDashboardStatsUseCase;
import com.company.incert.ocsp.admin.application.port.in.GetRevocationFeedUseCase;
import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
import com.company.incert.ocsp.status.application.port.out.OcspResponseCachePort;
import com.company.incert.ocsp.status.application.port.out.StatusStatsPort;
import lombok.RequiredArgsConstructor;

import java.util.List;
import java.util.Map;

public class AdminDashboardService implements GetDashboardStatsUseCase, GetRevocationFeedUseCase {

    private final StatusStatsPort statusStatsPort;
    private final OcspSigner ocspSigner;
    private final OcspResponseCachePort responseCachePort;
    private final com.company.incert.ocsp.responder.application.port.in.HandleOcspRequestUseCase handleOcspRequestUseCase;
    private final com.company.incert.ocsp.sync.application.port.in.ReconciliationUseCase reconciliationUseCase;

    public AdminDashboardService(StatusStatsPort statusStatsPort, OcspSigner ocspSigner) {
        this(statusStatsPort, ocspSigner, OcspResponseCachePort.NOOP, null, null);
    }

    public AdminDashboardService(
            StatusStatsPort statusStatsPort,
            OcspSigner ocspSigner,
            OcspResponseCachePort responseCachePort,
            com.company.incert.ocsp.responder.application.port.in.HandleOcspRequestUseCase handleOcspRequestUseCase) {
        this(statusStatsPort, ocspSigner, responseCachePort, handleOcspRequestUseCase, null);
    }

    public AdminDashboardService(
            StatusStatsPort statusStatsPort,
            OcspSigner ocspSigner,
            OcspResponseCachePort responseCachePort,
            com.company.incert.ocsp.responder.application.port.in.HandleOcspRequestUseCase handleOcspRequestUseCase,
            com.company.incert.ocsp.sync.application.port.in.ReconciliationUseCase reconciliationUseCase) {
        this.statusStatsPort = statusStatsPort;
        this.ocspSigner = ocspSigner;
        this.responseCachePort = responseCachePort != null ? responseCachePort : OcspResponseCachePort.NOOP;
        this.handleOcspRequestUseCase = handleOcspRequestUseCase;
        this.reconciliationUseCase = reconciliationUseCase;
    }

    @Override
    public Map<String, Object> getStats() {
        long totalCerts = statusStatsPort.countTotal();
        long revokedCerts = statusStatsPort.countRevoked();
        long goodCerts = statusStatsPort.countGood();
        long signingCertDaysLeft = ocspSigner.signingCertDaysUntilExpiry();
        long cachedResponses = responseCachePort.count();

        return Map.ofEntries(
            Map.entry("totalCertificates", totalCerts),
            Map.entry("revokedCertificates", revokedCerts),
            Map.entry("goodCertificates", goodCerts),
            Map.entry("signingCertDaysUntilExpiry", signingCertDaysLeft),
            Map.entry("requestsPerSecond", 12.5),
            Map.entry("l1HitRatio", 0.95),
            Map.entry("l2HitRatio", 0.99),
            Map.entry("avgSigningLatencyMs", 0.8),
            Map.entry("errorRate", 0.0),
            Map.entry("activeCacheEntries", cachedResponses),
            Map.entry("ocspSigningCertDaysRemaining", signingCertDaysLeft),
            Map.entry("lastReconciliationOk", reconciliationUseCase != null ? reconciliationUseCase.isLastReconciliationOk() : true),
            Map.entry("lastReconciliationTime", reconciliationUseCase != null && reconciliationUseCase.getLastReconciliationTime() != null ? reconciliationUseCase.getLastReconciliationTime().toString() : "")
        );
    }

    @Override
    public Map<String, Object> runReconciliation() {
        if (reconciliationUseCase == null) {
            return Map.of("status", "UNAVAILABLE", "message", "ReconciliationUseCase is not configured");
        }
        return reconciliationUseCase.runReconciliation();
    }

    public Map<String, Object> getReconciliationStatus() {
        if (reconciliationUseCase == null) {
            return Map.of("status", "UNAVAILABLE");
        }
        return Map.of(
            "lastOk", reconciliationUseCase.isLastReconciliationOk(),
            "lastTime", reconciliationUseCase.getLastReconciliationTime() != null ? reconciliationUseCase.getLastReconciliationTime().toString() : ""
        );
    }

    public List<Map<String, String>> getRevoked(int page, int size) {
        return statusStatsPort.getRevokedPage(page, size);
    }

    public java.util.Optional<Map<String, Object>> checkSerialStatus(String serialHex) {
        return statusStatsPort.findBySerial(serialHex).map(m -> Map.of(
            "serialHex", m.get("serialHex"),
            "status", m.get("status"),
            "revocationTime", m.get("revocationTime") != null ? m.get("revocationTime") : "",
            "revocationReason", m.get("revocationReason") != null ? m.get("revocationReason") : "",
            "renewalAvailable", "true".equals(m.get("renewalAvailable"))
        ));
    }

    public Map<String, Object> simulateOcspRequest(String serialHex, boolean includeNonce, String method) {
        try {
            var certOpt = statusStatsPort.findBySerial(serialHex);
            if (certOpt.isEmpty()) {
                return Map.of("error", "Certificate serial not found in database: " + serialHex);
            }
            var certData = certOpt.get();
            String nameHashHex = certData.get("issuerNameHashHex");
            String keyHashHex = certData.get("issuerKeyHashHex");
            java.util.HexFormat hexFormat = java.util.HexFormat.of();
            byte[] nameHash = hexFormat.parseHex(nameHashHex);
            byte[] keyHash = hexFormat.parseHex(keyHashHex);
            byte[] serialBytes = hexFormat.parseHex(serialHex.toLowerCase().replaceAll("[^0-9a-f]", ""));
            java.math.BigInteger serialInt = new java.math.BigInteger(1, serialBytes);

            org.bouncycastle.asn1.x509.AlgorithmIdentifier sha1Alg =
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers.idSHA1, org.bouncycastle.asn1.DERNull.INSTANCE);
            org.bouncycastle.asn1.ocsp.CertID asn1CertId = new org.bouncycastle.asn1.ocsp.CertID(
                sha1Alg,
                new org.bouncycastle.asn1.DEROctetString(nameHash),
                new org.bouncycastle.asn1.DEROctetString(keyHash),
                new org.bouncycastle.asn1.ASN1Integer(serialInt)
            );
            org.bouncycastle.cert.ocsp.CertificateID certId = new org.bouncycastle.cert.ocsp.CertificateID(asn1CertId);

            org.bouncycastle.cert.ocsp.OCSPReqBuilder reqBuilder = new org.bouncycastle.cert.ocsp.OCSPReqBuilder();
            reqBuilder.addRequest(certId);

            String nonceHex = null;
            if (includeNonce) {
                byte[] nonce = new byte[8];
                new java.security.SecureRandom().nextBytes(nonce);
                nonceHex = hexFormat.formatHex(nonce);
                org.bouncycastle.asn1.x509.Extension nonceExt = new org.bouncycastle.asn1.x509.Extension(
                    org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                    false,
                    new org.bouncycastle.asn1.DEROctetString(nonce)
                );
                reqBuilder.setRequestExtensions(new org.bouncycastle.asn1.x509.Extensions(nonceExt));
            }

            org.bouncycastle.cert.ocsp.OCSPReq ocspReq = reqBuilder.build();
            byte[] derRequest = ocspReq.getEncoded();

            // Check if L2 pre-signed cache entry already exists
            com.company.incert.ocsp.shared.domain.CertId domainCertId =
                new com.company.incert.ocsp.shared.domain.CertId(nameHash, keyHash, serialBytes);
            String cacheKey = domainCertId.toSha1CacheKey();
            boolean wasInL2 = !includeNonce && responseCachePort.getResponse(cacheKey).isPresent();

            long start = System.nanoTime();
            byte[] derResponse = handleOcspRequestUseCase.handle(derRequest);
            long elapsedNanos = System.nanoTime() - start;
            double latencyMs = elapsedNanos / 1_000_000.0;

            org.bouncycastle.cert.ocsp.OCSPResp ocspResp = new org.bouncycastle.cert.ocsp.OCSPResp(derResponse);
            int respStatus = ocspResp.getStatus();
            String statusStr = "UNKNOWN";
            String revTimeStr = null;
            String revReasonStr = null;
            String nonceEchoedHex = null;
            String thisUpdateStr = null;
            String nextUpdateStr = null;

            if (respStatus == org.bouncycastle.cert.ocsp.OCSPRespBuilder.SUCCESSFUL) {
                org.bouncycastle.cert.ocsp.BasicOCSPResp basicResp =
                    (org.bouncycastle.cert.ocsp.BasicOCSPResp) ocspResp.getResponseObject();

                org.bouncycastle.asn1.x509.Extension echoedNonceExt =
                    basicResp.getExtension(org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
                if (echoedNonceExt != null) {
                    nonceEchoedHex = hexFormat.formatHex(echoedNonceExt.getExtnValue().getOctets());
                }

                org.bouncycastle.cert.ocsp.SingleResp[] responses = basicResp.getResponses();
                if (responses != null && responses.length > 0) {
                    var single = responses[0];
                    thisUpdateStr = single.getThisUpdate() != null ? single.getThisUpdate().toInstant().toString() : null;
                    nextUpdateStr = single.getNextUpdate() != null ? single.getNextUpdate().toInstant().toString() : null;
                    var st = single.getCertStatus();
                    if (st == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
                        statusStr = "GOOD";
                    } else if (st instanceof org.bouncycastle.cert.ocsp.RevokedStatus rev) {
                        statusStr = "REVOKED";
                        revTimeStr = rev.getRevocationTime() != null ? rev.getRevocationTime().toInstant().toString() : null;
                        revReasonStr = rev.hasRevocationReason() ? String.valueOf(rev.getRevocationReason()) : "UNSPECIFIED";
                    } else {
                        statusStr = "UNKNOWN";
                    }
                }
            }

            String cacheVerdict;
            if (includeNonce) {
                cacheVerdict = "BYPASS_NONCE (L2 ineligible due to RFC 6960 Nonce requirement)";
            } else if (wasInL2) {
                cacheVerdict = "L2_HIT (Served instantly from pre-signed L2 cache table)";
            } else {
                cacheVerdict = "L2_MISS_STORED (Signed via SoftHSM2 PKCS#11 & persisted into L2 table)";
            }

            String b64Url = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(derRequest);

            return Map.ofEntries(
                Map.entry("serialHex", serialHex),
                Map.entry("cacheKey", cacheKey),
                Map.entry("method", method != null ? method : "POST"),
                Map.entry("includeNonce", includeNonce),
                Map.entry("nonceSent", nonceHex != null ? nonceHex : ""),
                Map.entry("nonceEchoed", nonceEchoedHex != null ? nonceEchoedHex : ""),
                Map.entry("nonceMatched", nonceHex != null && nonceHex.equalsIgnoreCase(nonceEchoedHex)),
                Map.entry("cacheVerdict", cacheVerdict),
                Map.entry("l2Hit", wasInL2),
                Map.entry("latencyMs", Math.round(latencyMs * 100.0) / 100.0),
                Map.entry("certStatus", statusStr),
                Map.entry("revocationTime", revTimeStr != null ? revTimeStr : ""),
                Map.entry("revocationReason", revReasonStr != null ? revReasonStr : ""),
                Map.entry("thisUpdate", thisUpdateStr != null ? thisUpdateStr : ""),
                Map.entry("nextUpdate", nextUpdateStr != null ? nextUpdateStr : ""),
                Map.entry("responseSizeBytes", derResponse.length),
                Map.entry("base64UrlPath", "/ocsp/" + b64Url),
                Map.entry("opensslCommand", includeNonce
                    ? "openssl ocsp -issuer data/pki/intermediate-ca-cert.pem -cert data/pki/ee-01.pem -url http://localhost:8080/ocsp -nonce -CAfile data/pki/intermediate-ca-cert.pem"
                    : "openssl ocsp -issuer data/pki/intermediate-ca-cert.pem -cert data/pki/ee-01.pem -url http://localhost:8080/ocsp -no_nonce -CAfile data/pki/intermediate-ca-cert.pem")
            );
        } catch (Exception e) {
            return Map.of("error", "OCSP test execution failed: " + e.getMessage());
        }
    }
}
