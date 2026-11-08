package com.company.incert.ocsp.responder.application.service;

import com.company.incert.ocsp.responder.application.port.in.HandleOcspRequestUseCase;
import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.shared.domain.CertificateStatus;
import com.company.incert.ocsp.shared.domain.RevocationReason;
import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
import com.company.incert.ocsp.status.application.port.in.LookupStatusUseCase;
import com.company.incert.ocsp.status.application.port.out.OcspResponseCachePort;
import com.company.incert.ocsp.shared.CertificateStatusRecord;
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

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

/**
 * Core OCSP request handler — application service.
 * Depends only on domain + ports (LookupStatusUseCase, OcspSigner).
 * No adapters, no Spring MVC, no JPA here.
 */
@Slf4j
public class OcspRequestHandlerService implements HandleOcspRequestUseCase {

    private static final Duration NEXT_UPDATE_WINDOW = Duration.ofHours(1);

    private final LookupStatusUseCase statusLookup;
    private final OcspSigner signer;
    private final MeterRegistry meterRegistry;
    private final OcspResponseCachePort responseCachePort;

    public OcspRequestHandlerService(
            LookupStatusUseCase statusLookup,
            OcspSigner signer,
            MeterRegistry meterRegistry) {
        this(statusLookup, signer, meterRegistry, OcspResponseCachePort.NOOP);
    }

    public OcspRequestHandlerService(
            LookupStatusUseCase statusLookup,
            OcspSigner signer,
            MeterRegistry meterRegistry,
            OcspResponseCachePort responseCachePort) {
        this.statusLookup = statusLookup;
        this.signer = signer;
        this.meterRegistry = meterRegistry;
        this.responseCachePort = responseCachePort != null ? responseCachePort : OcspResponseCachePort.NOOP;
    }

    @Override
    public byte[] handle(byte[] derRequest) {
        Timer.Sample sample = Timer.start(meterRegistry);
        try {
            return doHandle(derRequest);
        } catch (MalformedRequestException e) {
            log.warn("Malformed OCSP request: {}", e.getMessage());
            meterRegistry.counter("ocsp.request.error", "reason", "malformed").increment();
            return buildErrorResponse(OCSPRespBuilder.MALFORMED_REQUEST);
        } catch (Exception e) {
            log.error("OCSP processing error: {}", e.getMessage(), e);
            meterRegistry.counter("ocsp.request.error", "reason", "internal").increment();
            return buildErrorResponse(OCSPRespBuilder.INTERNAL_ERROR);
        } finally {
            sample.stop(meterRegistry.timer("ocsp.request.duration"));
        }
    }

    private byte[] doHandle(byte[] derRequest) throws Exception {
        // 1. Parse
        OCSPReq ocspReq = parseRequest(derRequest);
        Extension nonce = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

        Req[] requests = ocspReq.getRequestList();
        if (requests == null || requests.length == 0) {
            return buildErrorResponse(OCSPRespBuilder.MALFORMED_REQUEST);
        }

        // 2. Build response for first requested CertID (RFC 6960 single cert path)
        Req req = requests[0];
        CertificateID certId = req.getCertID();
        CertId domainCertId = new CertId(
            certId.getIssuerNameHash(),
            certId.getIssuerKeyHash(),
            certId.getSerialNumber().toByteArray()
        );

        // Check L2 response cache when no nonce is present
        String cacheKey = domainCertId.toSha1CacheKey();
        if (nonce == null) {
            Optional<byte[]> cached = responseCachePort.getResponse(cacheKey);
            if (cached.isPresent()) {
                meterRegistry.counter("ocsp.response.cache.hit").increment();
                log.debug("Served OCSP response from L2 cache for key={}", cacheKey);
                return cached.get();
            }
        }

        // 3. Look up status (cache → DB)
        Optional<CertificateStatusRecord> statusOpt = statusLookup.lookup(domainCertId);

        // 4. Build response
        Instant now = Instant.now();
        Instant nextUpdate = now.plus(NEXT_UPDATE_WINDOW);

        X509CertificateHolder[] chain = signer.getSignerChain();
        RespID respId = new RespID(chain[0].getSubject());
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(respId);

        // Echo nonce if present
        if (nonce != null) {
            builder.setResponseExtensions(new Extensions(nonce));
        }

        // Map status
        org.bouncycastle.cert.ocsp.CertificateStatus bcStatus;
        if (statusOpt.isEmpty()) {
            bcStatus = new UnknownStatus();
            meterRegistry.counter("ocsp.response.status", "status", "unknown").increment();
        } else {
            CertificateStatusRecord record = statusOpt.get();
            if (record.status() == CertificateStatus.REVOKED) {
                int reasonCode = record.revocationReason() != null
                    ? record.revocationReason().getCode() : RevocationReason.UNSPECIFIED.getCode();
                bcStatus = new RevokedStatus(
                    record.revocationTime() != null ? Date.from(record.revocationTime()) : Date.from(now),
                    reasonCode
                );
                meterRegistry.counter("ocsp.response.status", "status", "revoked").increment();
            } else {
                bcStatus = org.bouncycastle.cert.ocsp.CertificateStatus.GOOD;
                meterRegistry.counter("ocsp.response.status", "status", "good").increment();
            }
        }

        builder.addResponse(certId, bcStatus, Date.from(now), Date.from(nextUpdate), null);

        // 5. Sign
        ContentSigner contentSigner = signer.createContentSigner();
        BasicOCSPResp basicResp = builder.build(contentSigner, chain, Date.from(now));

        OCSPRespBuilder respBuilder = new OCSPRespBuilder();
        OCSPResp ocspResp = respBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicResp);

        byte[] encodedResponse = ocspResp.getEncoded();

        // 6. Save to response cache if no nonce
        if (nonce == null) {
            responseCachePort.saveResponse(cacheKey, encodedResponse, now, nextUpdate);
        }

        return encodedResponse;
    }

    private OCSPReq parseRequest(byte[] der) throws MalformedRequestException {
        if (der == null || der.length == 0 || der.length > 10 * 1024) {
            throw new MalformedRequestException("Invalid request size: " + (der == null ? 0 : der.length));
        }
        try {
            return new OCSPReq(der);
        } catch (IOException e) {
            throw new MalformedRequestException("Failed to parse DER: " + e.getMessage());
        }
    }

    private byte[] buildErrorResponse(int status) {
        try {
            return new OCSPRespBuilder().build(status, null).getEncoded();
        } catch (Exception e) {
            log.error("Failed to build error response", e);
            return new byte[0];
        }
    }

    public static class MalformedRequestException extends RuntimeException {
        public MalformedRequestException(String msg) {
            super(msg);
        }
    }
}
