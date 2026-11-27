package lu.incert.ocsp.responder.service;


import lu.incert.ocsp.status.service.CertificateStatusService;
import lu.incert.ocsp.responder.config.OcspResponderProperties;
import lu.incert.ocsp.status.entity.CertificateStatus;
import lu.incert.ocsp.status.entity.RevocationReason;
import lu.incert.ocsp.status.entity.RevocationStatus;
import lu.incert.ocsp.signing.hsm.OcspSigner;
import lu.incert.ocsp.signing.hsm.SignerNotConfiguredException;
import lu.incert.ocsp.signing.hsm.UnauthorizedIssuerException;
import lu.incert.ocsp.signing.port.DeviceLockedException;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
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

    private final CertificateStatusService statusService;
    private final OcspSigner signer;
    private final MeterRegistry meterRegistry;
    private final OcspResponderProperties properties;

    public OcspResponderService(
            CertificateStatusService statusService,
            OcspSigner signer,
            MeterRegistry meterRegistry,
            OcspResponderProperties properties) {
        this.statusService = statusService;
        this.signer = signer;
        this.meterRegistry = meterRegistry;
        this.properties = properties;
    }

    public record OcspReadinessStatus(
            boolean ocspReady,
            String status,
            String nodeId,
            String providerId,
            String keyLabel,
            String activationState,
            long signingCertDaysRemaining,
            String detail
    ) {}

    public String getNodeId() {
        String envNode = System.getenv("OCSP_NODE_ID");
        if (envNode != null && !envNode.isBlank()) {
            return envNode.trim();
        }
        String host = System.getenv("HOSTNAME");
        return (host != null && !host.isBlank()) ? host.trim() : "ocsp-node-1";
    }

    /**
     * Pattern A Load-Balancer Readiness Gate: returns {@code ocspReady=true} (HTTP 200) only when
     * this node has an active non-expired signing certificate AND its backing HSM device is ACTIVE
     * in memory with the required signing key. Returns {@code ocspReady=false} (HTTP 503) when LOCKED.
     */
    public OcspReadinessStatus checkReadiness() {
        String nodeId = getNodeId();
        String activeProviderId = signer.getActiveProviderId();
        String defaultProviderId = signer.getDefaultProviderId();
        String targetProviderId = (activeProviderId != null && !activeProviderId.isBlank() && !"default".equalsIgnoreCase(activeProviderId))
                ? activeProviderId
                : defaultProviderId;
        String activeKeyLabel = signer.getActiveKeyLabel();
        long daysRemaining = signer.signingCertDaysUntilExpiry();

        if (daysRemaining < 0) {
            return new OcspReadinessStatus(
                    false,
                    "NO_ACTIVE_SIGNING_CERT",
                    nodeId,
                    targetProviderId,
                    activeKeyLabel,
                    "LOCKED",
                    daysRemaining,
                    "No active non-expired OCSP signing certificate is configured"
            );
        }

        java.util.List<ProviderDeviceInfo> providers = signer.listProviders();
        if (!providers.isEmpty()) {
            ProviderDeviceInfo device = providers.stream()
                    .filter(p -> p.providerId().equals(targetProviderId))
                    .findFirst()
                    .orElse(providers.get(0));

            if (!device.healthy()) {
                return new OcspReadinessStatus(
                        false,
                        "HSM_DEVICE_LOCKED",
                        nodeId,
                        device.providerId(),
                        activeKeyLabel,
                        "LOCKED",
                        daysRemaining,
                        "HSM device '" + device.providerId() + "' is LOCKED on node '" + nodeId
                                + "' — awaiting manual PIN unlock (Pattern A Readiness Gate)"
                );
            }

            if (device.keyLabels() != null && !device.keyLabels().isEmpty()
                    && activeKeyLabel != null && !device.keyLabels().contains(activeKeyLabel)) {
                return new OcspReadinessStatus(
                        false,
                        "HSM_KEY_NOT_FOUND",
                        nodeId,
                        device.providerId(),
                        activeKeyLabel,
                        "ACTIVE",
                        daysRemaining,
                        "Private key '" + activeKeyLabel + "' not found on HSM device '" + device.providerId() + "'"
                );
            }
        }

        return new OcspReadinessStatus(
                true,
                "READY",
                nodeId,
                targetProviderId,
                activeKeyLabel,
                "ACTIVE",
                daysRemaining,
                "Node '" + nodeId + "' HSM signer is ACTIVE and ready to sign RFC 6960 OCSP responses"
        );
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
        } catch (UnauthorizedIssuerException e) {
            // RFC 6960 §2.3 / §4.2.2.2: no active signing certificate is authorized for the requested Issuing CA.
            // Return unsigned UNAUTHORIZED (6) without touching the HSM.
            log.warn("OCSP request unauthorized: {}", e.getMessage());
            meterRegistry.counter("ocsp.request.error", "reason", "unauthorized").increment();
            return buildErrorResponse(OCSPRespBuilder.UNAUTHORIZED);
        } catch (SignerNotConfiguredException | DeviceLockedException e) {
            // RFC 6960 tryLater: responder is up but signing certificate is missing or HSM device is LOCKED.
            log.warn("OCSP request not answered: {}", e.getMessage());
            meterRegistry.counter("ocsp.request.error", "reason", "no_signer").increment();
            return buildErrorResponse(OCSPRespBuilder.TRY_LATER);
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
        if (requests.length > properties.getMaxCertIds()) {
            throw new MalformedRequestException("Too many CertIDs: " + requests.length);
        }

        Extension nonce = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        validateNonce(nonce);

        Instant now = Instant.now();
        Date thisUpdate = Date.from(now);
        Date nextUpdate = Date.from(now.plus(properties.getNextUpdateWindow()));

        // Select the signing certificate authorized for the issuing CA of the request (RFC 6960 §4.2.2.2).
        // In multi-CertID requests, all CertIDs must belong to the same Issuing CA so one signer cannot
        // inadvertently sign status responses for an unauthorized CA.
        CertificateID primaryCertId = requests[0].getCertID();
        for (int i = 1; i < requests.length; i++) {
            CertificateID other = requests[i].getCertID();
            if (!java.util.Arrays.equals(primaryCertId.getIssuerNameHash(), other.getIssuerNameHash())
                    || !java.util.Arrays.equals(primaryCertId.getIssuerKeyHash(), other.getIssuerKeyHash())) {
                throw new UnauthorizedIssuerException(
                        "OCSP request mixes multiple Issuing CAs in a single BasicOCSPResponse");
            }
        }
        OcspSigner.SigningSelection selection = signer.selectSigner(primaryCertId);
        X509CertificateHolder[] chain = selection.chain();
        BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(chain[0].getSubject()));

        for (Req req : requests) {
            CertificateID certId = req.getCertID();
            // Same canonical form as CertificateStatusService.parseSerial (minimal two's complement).
            byte[] serialBytes = certId.getSerialNumber().toByteArray();
            Optional<RevocationStatus> status = statusService.findByCertId(
                certId.getIssuerNameHash(),
                certId.getIssuerKeyHash(),
                serialBytes);
            builder.addResponse(certId, toBcStatus(status, now), thisUpdate, nextUpdate, null);
        }

        // RFC 6960 §4.4.1: echo the request nonce so the client can bind the response to its request.
        if (nonce != null) {
            builder.setResponseExtensions(new Extensions(nonce));
            meterRegistry.counter("ocsp.request.nonce", "present", "true").increment();
        } else {
            meterRegistry.counter("ocsp.request.nonce", "present", "false").increment();
        }

        BasicOCSPResp basicResp = builder.build(selection.contentSigner(), chain, thisUpdate);
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

    private void validateNonce(Extension nonce) {
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
        int maxNonceOctets = properties.getMaxNonceOctets();
        if (value.length < 1 || value.length > maxNonceOctets) {
            throw new MalformedRequestException("Nonce length must be 1.." + maxNonceOctets + " octets (RFC 8954)");
        }
    }

    private OCSPReq parseRequest(byte[] der) {
        int maxRequestBytes = properties.getMaxRequestBytes();
        if (der == null || der.length == 0 || der.length > maxRequestBytes) {
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

    /**
     * BigInteger.toByteArray() prepends a 0x00 sign byte when the high bit of the
     * most-significant byte is set (to signal a positive value in two's complement).
     * Strip it so the byte array matches the raw hex stored by the KMS.
     */
    public static class MalformedRequestException extends RuntimeException {
        public MalformedRequestException(String msg) {
            super(msg);
        }
    }
}

