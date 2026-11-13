package com.company.incert.ocsp.service;

import com.company.incert.ocsp.entity.CertificateStatus;
import com.company.incert.ocsp.entity.RevocationReason;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.signing.OcspSigner;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;

/**
 * RFC 6960 OCSP responder.
 * <p>
 * Every request is answered with a freshly signed response:
 * parse DER request → look up each CertID in the database → build BasicOCSPResponse →
 * echo the nonce (if any) → sign with the PKCS#11 key. There is no response cache.
 */
@Slf4j
@Service
public class OcspResponderService {

    /** Maximum DER request size accepted (protects the parser). */
    private static final int MAX_REQUEST_BYTES = 10 * 1024;
    /** Maximum number of CertIDs answered in a single request. */
    private static final int MAX_CERT_IDS = 10;
    /** RFC 8954: nonce value length must be 1..32 octets. */
    private static final int MAX_NONCE_OCTETS = 32;

    private final CertificateStatusService statusService;
    private final OcspSigner signer;
    private final MeterRegistry meterRegistry;
    private final Duration nextUpdateWindow;

    public OcspResponderService(
            CertificateStatusService statusService,
            OcspSigner signer,
            MeterRegistry meterRegistry,
            @Value("${ocsp.responder.next-update-window:PT1H}") Duration nextUpdateWindow) {
        this.statusService = statusService;
        this.signer = signer;
        this.meterRegistry = meterRegistry;
        this.nextUpdateWindow = nextUpdateWindow;
    }

    /** Handles a DER-encoded OCSPRequest and always returns a DER-encoded OCSPResponse. */
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
        OCSPReq ocspReq = parseRequest(derRequest);

        Req[] requests = ocspReq.getRequestList();
        if (requests == null || requests.length == 0) {
            throw new MalformedRequestException("Request contains no CertID");
        }
        if (requests.length > MAX_CERT_IDS) {
            throw new MalformedRequestException("Too many CertIDs: " + requests.length);
        }

        Extension nonce = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        validateNonce(nonce);

        Instant now = Instant.now();
        Date thisUpdate = Date.from(now);
        Date nextUpdate = Date.from(now.plus(nextUpdateWindow));

        X509CertificateHolder[] chain = signer.getSignerChain();
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(chain[0].getSubject()));

        for (Req req : requests) {
            CertificateID certId = req.getCertID();
            Optional<RevocationStatus> status = statusService.findByCertId(
                certId.getIssuerNameHash(),
                certId.getIssuerKeyHash(),
                certId.getSerialNumber().toByteArray());
            builder.addResponse(certId, toBcStatus(status, now), thisUpdate, nextUpdate, null);
        }

        // RFC 6960 §4.4.1: echo the request nonce so the client can bind the response to its request.
        if (nonce != null) {
            builder.setResponseExtensions(new Extensions(nonce));
            meterRegistry.counter("ocsp.request.nonce", "present", "true").increment();
        } else {
            meterRegistry.counter("ocsp.request.nonce", "present", "false").increment();
        }

        BasicOCSPResp basicResp = builder.build(signer.createContentSigner(), chain, thisUpdate);
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResp).getEncoded();
    }

    private org.bouncycastle.cert.ocsp.CertificateStatus toBcStatus(Optional<RevocationStatus> statusOpt, Instant now) {
        if (statusOpt.isEmpty()) {
            meterRegistry.counter("ocsp.response.status", "status", "unknown").increment();
            return new UnknownStatus();
        }
        RevocationStatus status = statusOpt.get();
        if (status.getStatus() == CertificateStatus.REVOKED) {
            RevocationReason reason = status.revocationReasonEnum();
            meterRegistry.counter("ocsp.response.status", "status", "revoked").increment();
            return new RevokedStatus(
                Date.from(status.getRevocationTime() != null ? status.getRevocationTime() : now),
                (reason != null ? reason : RevocationReason.UNSPECIFIED).getCode());
        }
        if (status.getStatus() == CertificateStatus.UNKNOWN) {
            meterRegistry.counter("ocsp.response.status", "status", "unknown").increment();
            return new UnknownStatus();
        }
        meterRegistry.counter("ocsp.response.status", "status", "good").increment();
        return org.bouncycastle.cert.ocsp.CertificateStatus.GOOD;
    }

    private static void validateNonce(Extension nonce) {
        if (nonce == null) {
            return;
        }
        byte[] value = nonce.getExtnValue().getOctets();
        // The extension value is normally an OCTET STRING wrapping the nonce bytes.
        try {
            value = ASN1OctetString.getInstance(value).getOctets();
        } catch (Exception ignored) {
            // Some clients put raw bytes; accept them as-is.
        }
        if (value.length < 1 || value.length > MAX_NONCE_OCTETS) {
            throw new MalformedRequestException("Nonce length must be 1.." + MAX_NONCE_OCTETS + " octets (RFC 8954)");
        }
    }

    private static OCSPReq parseRequest(byte[] der) {
        if (der == null || der.length == 0 || der.length > MAX_REQUEST_BYTES) {
            throw new MalformedRequestException("Invalid request size: " + (der == null ? 0 : der.length));
        }
        try {
            return new OCSPReq(der);
        } catch (IOException | RuntimeException e) {
            throw new MalformedRequestException("Failed to parse DER: " + e.getMessage());
        }
    }

    private static byte[] buildErrorResponse(int status) {
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

