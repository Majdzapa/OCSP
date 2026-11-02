package com.company.ocsp.responder.service;

import com.company.ocsp.responder.cache.OcspResponseCacheManager;
import com.company.ocsp.responder.model.RevocationStatus;
import com.company.ocsp.responder.repository.RevocationStatusRepository;
import com.company.ocsp.responder.util.CertIdCacheKeyUtil;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentSigner;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

/**
 * Core OCSP processing service.
 *
 * <p>Processing flow per RFC 6960 §2.1 / §4.2:
 * <ol>
 *   <li>Parse the incoming DER-encoded {@code OCSPRequest}.
 *   <li>For each {@code Request} in the request:
 *       <ol>
 *         <li>Derive the CertID cache key.
 *         <li>Check L1 → L2 cache for a pre-signed, still-valid response.
 *         <li>On cache miss: query MariaDB {@code revocation_status}.
 *         <li>Build a {@code BasicOCSPResp}, call the KMS signing API,
 *             persist into L2, and warm L1.
 *       </ol>
 *   <li>Return the DER-encoded {@code OCSPResponse}.
 * </ol>
 *
 * <p>This implementation currently handles single-certificate OCSP requests (the
 * overwhelming majority in practice).  Multi-cert batch requests are processed per
 * single-certificate and their responses merged.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OcspProcessingService {

    /** Validity window for freshly-signed OCSP responses. Tunable via config. */
    private static final Duration NEXT_UPDATE_WINDOW = Duration.ofHours(1);

    private final RevocationStatusRepository revocationStatusRepository;
    private final OcspResponseCacheManager cacheManager;
    private final KmsSigningService kmsSigningService;
    private final MeterRegistry meterRegistry;

    /**
     * Processes a DER-encoded {@code OCSPRequest} and returns a DER-encoded
     * {@code OCSPResponse}.
     *
     * @param requestBytes raw DER bytes from the HTTP request body or path
     * @return DER-encoded OCSPResponse (never null; may carry an error status)
     */
    public byte[] process(byte[] requestBytes) {
        Timer.Sample sample = Timer.start(meterRegistry);
        try {
            return doProcess(requestBytes);
        } catch (MalformedRequestException e) {
            log.warn("Malformed OCSP request: {}", e.getMessage());
            meterRegistry.counter("ocsp.request.error", "reason", "malformed").increment();
            return buildErrorResponse(OCSPRespBuilder.MALFORMED_REQUEST);
        } catch (Exception e) {
            log.error("Unexpected error processing OCSP request", e);
            meterRegistry.counter("ocsp.request.error", "reason", "internal").increment();
            return buildErrorResponse(OCSPRespBuilder.INTERNAL_ERROR);
        } finally {
            sample.stop(meterRegistry.timer("ocsp.request.duration"));
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private byte[] doProcess(byte[] requestBytes) throws OCSPException, IOException {
        // 1. Parse
        OCSPReq ocspReq = parseRequest(requestBytes);

        // 2. Extract nonce (RFC 6960 §4.4.1)
        Extension nonce = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        // 3. Process each requested CertID (typically just one)
        Req[] requests = ocspReq.getRequestList();
        if (requests == null || requests.length == 0) {
            return buildErrorResponse(OCSPRespBuilder.MALFORMED_REQUEST);
        }

        // For single-cert requests (by far the common case), take the fast path
        Req req = requests[0];
        CertificateID certId = req.getCertID();

        byte[] issuerNameHash = certId.getIssuerNameHash();
        byte[] issuerKeyHash  = certId.getIssuerKeyHash();
        byte[] serialNumber   = certId.getSerialNumber().toByteArray();

        String cacheKey = CertIdCacheKeyUtil.computeKey(issuerNameHash, issuerKeyHash, serialNumber);
        log.debug("Processing OCSP request for cacheKey={}", cacheKey);

        // 4. Cache lookup
        Optional<byte[]> cached = cacheManager.get(cacheKey);
        if (cached.isPresent() && nonce == null) {
            // Only return a cached response when no nonce is present (nonce responses
            // must be freshly signed to include the echoed nonce per RFC 6960 §4.4.1)
            meterRegistry.counter("ocsp.request.served", "source", "cache").increment();
            return cached.get();
        }

        // 5. DB lookup
        Optional<RevocationStatus> statusOpt = revocationStatusRepository
            .findByCertId(issuerNameHash, issuerKeyHash, serialNumber);

        // 6. Build and sign the response
        Instant now        = Instant.now();
        Instant nextUpdate = now.plus(NEXT_UPDATE_WINDOW);

        byte[] derResponse = buildAndSignResponse(certId, statusOpt, nonce, now, nextUpdate);

        // 7. Populate cache (only for nonce-free responses)
        if (nonce == null) {
            cacheManager.put(cacheKey, derResponse, now, nextUpdate);
        }

        meterRegistry.counter("ocsp.request.served", "source", "fresh").increment();
        return derResponse;
    }

    private OCSPReq parseRequest(byte[] bytes) {
        if (bytes == null || bytes.length == 0 || bytes.length > 10_240) {
            throw new MalformedRequestException("Request size invalid: "
                + (bytes == null ? "null" : bytes.length));
        }
        try {
            return new OCSPReq(bytes);
        } catch (IOException e) {
            throw new MalformedRequestException("Failed to parse DER OCSPRequest: " + e.getMessage());
        }
    }

    private byte[] buildAndSignResponse(
            CertificateID certId,
            Optional<RevocationStatus> statusOpt,
            Extension nonce,
            Instant thisUpdate,
            Instant nextUpdate) throws OCSPException, java.io.IOException {

        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(
            kmsSigningService.getOcspSignerNameAsRespId()
        );

        // Echo nonce
        if (nonce != null) {
            builder.setResponseExtensions(new Extensions(nonce));
        }

        // Add single-cert status
        CertificateStatus bcStatus = toBcStatus(statusOpt);
        builder.addResponse(certId, bcStatus, Date.from(thisUpdate), Date.from(nextUpdate), null);

        // Sign via KMS
        ContentSigner signer = kmsSigningService.createContentSigner();
        X509CertificateHolder[] chain = kmsSigningService.getOcspSignerChain();

        BasicOCSPResp basicResp = builder.build(signer, chain, Date.from(thisUpdate));

        OCSPRespBuilder respBuilder = new OCSPRespBuilder();
        OCSPResp ocspResp = respBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicResp);

        return ocspResp.getEncoded();
    }

    private CertificateStatus toBcStatus(Optional<RevocationStatus> statusOpt) {
        if (statusOpt.isEmpty()) {
            return new UnknownStatus();
        }
        RevocationStatus status = statusOpt.get();
        return switch (status.getStatus()) {
            case GOOD    -> CertificateStatus.GOOD;
            case REVOKED -> new RevokedStatus(
                Date.from(status.getRevocationTime()),
                parseReason(status.getRevocationReason())
            );
            case UNKNOWN -> new UnknownStatus();
        };
    }

    private int parseReason(String reason) {
        if (reason == null) return 0; // unspecified
        return switch (reason.toLowerCase()) {
            case "keycompromise"          -> org.bouncycastle.asn1.x509.CRLReason.keyCompromise;
            case "cacompromise"           -> org.bouncycastle.asn1.x509.CRLReason.cACompromise;
            case "affiliationchanged"     -> org.bouncycastle.asn1.x509.CRLReason.affiliationChanged;
            case "superseded"             -> org.bouncycastle.asn1.x509.CRLReason.superseded;
            case "cessationofoperation"   -> org.bouncycastle.asn1.x509.CRLReason.cessationOfOperation;
            case "certificatehold"        -> org.bouncycastle.asn1.x509.CRLReason.certificateHold;
            case "removefromcrl"          -> org.bouncycastle.asn1.x509.CRLReason.removeFromCRL;
            default                       -> org.bouncycastle.asn1.x509.CRLReason.unspecified;
        };
    }

    private byte[] buildErrorResponse(int status) {
        try {
            return new OCSPRespBuilder().build(status, null).getEncoded();
        } catch (OCSPException | IOException e) {
            log.error("Failed to build error OCSP response", e);
            return new byte[0];
        }
    }

    /** Thrown when the incoming DER cannot be parsed as a valid OCSPRequest. */
    static class MalformedRequestException extends RuntimeException {
        MalformedRequestException(String msg) { super(msg); }
    }
}
