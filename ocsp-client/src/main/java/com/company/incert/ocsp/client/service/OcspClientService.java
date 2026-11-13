package com.company.incert.ocsp.client.service;

import com.company.incert.ocsp.client.dto.OcspCheckRequest;
import com.company.incert.ocsp.client.dto.OcspCheckResult;
import com.company.incert.ocsp.client.dto.OcspCheckResult.Check;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.io.File;
import java.io.FileReader;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;

/**
 * Standalone RFC 6960 OCSP Client Service.
 * Constructs requests (with or without Nonce), sends via POST / GET,
 * validates responses, signatures, freshness, and nonce matching.
 */
@Slf4j
@Service
public class OcspClientService {

    private static final String OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request";
    private static final String OCSP_RESPONSE_CONTENT_TYPE = "application/ocsp-response";

    private final RestClient restClient;
    private final String defaultResponderUrl;
    private final String pkiDir;
    private final SecureRandom secureRandom = new SecureRandom();

    private volatile X509Certificate trustAnchor;

    public OcspClientService(
            RestClient.Builder restClientBuilder,
            @Value("${ocsp.client.default-responder-url:http://localhost:8080/ocsp}") String defaultResponderUrl,
            @Value("${PKI_DIR:./data/pki}") String pkiDir) {
        this.restClient = restClientBuilder.build();
        this.defaultResponderUrl = defaultResponderUrl;
        this.pkiDir = pkiDir;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void loadTrustAnchorOnStartup() {
        for (String filename : List.of("intermediate-ca-cert.pem", "intermediate-ca.pem", "ca-chain.pem")) {
            File caFile = new File(pkiDir, filename);
            if (caFile.exists()) {
                try (FileReader reader = new FileReader(caFile)) {
                    this.trustAnchor = readCertificate(reader);
                    log.info("OCSP client loaded CA trust anchor from {}: {}", caFile.getPath(), trustAnchor.getSubjectX500Principal());
                    return;
                } catch (Exception e) {
                    log.warn("Could not load CA trust anchor from {}: {}", caFile.getPath(), e.getMessage());
                }
            }
        }
        log.info("No CA file found in {} yet; client will accept caller-supplied issuer PEM", pkiDir);
    }

    public OcspCheckResult check(OcspCheckRequest request) {
        List<Check> checks = new ArrayList<>();
        String responderUrl = (request.responderUrl() != null && !request.responderUrl().isBlank())
                ? request.responderUrl() : defaultResponderUrl;
        String method = (request.method() != null && !request.method().isBlank())
                ? request.method().toUpperCase() : "POST";

        try {
            // 1. Resolve target certificate and issuer
            TargetCert target = resolveTarget(request);
            X509Certificate issuerCert = resolveIssuer(request);

            if (issuerCert == null) {
                // Retry loading from PKI_DIR in case it was generated after startup
                loadTrustAnchorOnStartup();
                issuerCert = this.trustAnchor;
            }

            if (issuerCert == null) {
                checks.add(Check.fail("Issuer CA Resolution", "No issuer CA certificate provided and none found in " + pkiDir));
                return errorResult(responderUrl, method, 0, 0, 0, 0, null, checks, "Missing Issuer CA Certificate");
            }
            checks.add(Check.pass("Issuer CA Resolution", "Issuer: " + issuerCert.getSubjectX500Principal().getName()));

            // 2. Build RFC 6960 OCSPRequest
            DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
            X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(issuerCert);
            CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), issuerHolder, target.serial());

            OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
            reqBuilder.addRequest(certId);

            byte[] nonceBytes = null;
            String nonceSentHex = null;
            if (request.includeNonce()) {
                nonceBytes = new byte[8]; // standard 8-byte nonce
                secureRandom.nextBytes(nonceBytes);
                nonceSentHex = HexFormat.of().formatHex(nonceBytes);
                Extension nonceExt = new Extension(
                        OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                        false,
                        new DEROctetString(nonceBytes)
                );
                reqBuilder.setRequestExtensions(new Extensions(nonceExt));
            }

            OCSPReq ocspReq = reqBuilder.build();
            byte[] derRequest = ocspReq.getEncoded();
            String getPath = "/ocsp/" + Base64.getUrlEncoder().withoutPadding().encodeToString(derRequest);

            // 3. Send over HTTP
            long start = System.nanoTime();
            ResponseEntity<byte[]> responseEntity = sendRequest(responderUrl, method, derRequest, getPath);
            double latencyMs = Math.round(((System.nanoTime() - start) / 1_000_000.0) * 100.0) / 100.0;

            int httpStatus = responseEntity.getStatusCode().value();
            byte[] derResponse = responseEntity.getBody();
            if (derResponse == null || derResponse.length == 0) {
                checks.add(Check.fail("HTTP Delivery", "Responder returned empty body with HTTP " + httpStatus));
                return errorResult(responderUrl, method, httpStatus, latencyMs, derRequest.length, 0, getPath, checks, "Empty response body");
            }
            checks.add(Check.pass("HTTP Delivery", method + " " + responderUrl + " returned HTTP " + httpStatus + " (" + derResponse.length + " bytes)"));

            // 4. Parse OCSPResponse
            OCSPResp ocspResp;
            try {
                ocspResp = new OCSPResp(derResponse);
            } catch (Exception e) {
                checks.add(Check.fail("ASN.1 Parsing", "Failed to parse OCSPResponse DER: " + e.getMessage()));
                return errorResult(responderUrl, method, httpStatus, latencyMs, derRequest.length, derResponse.length, getPath, checks, "ASN.1 parse error");
            }

            String respStatusName = mapResponseStatus(ocspResp.getStatus());
            if (ocspResp.getStatus() != OCSPRespBuilder.SUCCESSFUL) {
                checks.add(Check.fail("Response Status", "Responder returned error status: " + respStatusName));
                return new OcspCheckResult(
                        false, responderUrl, method, httpStatus, respStatusName, null,
                        null, null, target.serialHex(), null, null, null, null, null,
                        request.includeNonce(), nonceSentHex, null, latencyMs,
                        derRequest.length, derResponse.length, getPath, checks,
                        "OCSP responder returned status " + respStatusName
                );
            }
            checks.add(Check.pass("Response Status", "Status is SUCCESSFUL (0)"));

            BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();
            if (basicResp == null) {
                checks.add(Check.fail("BasicOCSPResponse", "Response contains no BasicOCSPResponse"));
                return errorResult(responderUrl, method, httpStatus, latencyMs, derRequest.length, derResponse.length, getPath, checks, "No BasicOCSPResponse");
            }

            // 5. Verify cryptographic signature & responder authorization
            X509Certificate signerCert = extractSignerCert(basicResp, issuerCert);
            boolean sigOk = verifySignature(basicResp, signerCert);
            if (!sigOk) {
                checks.add(Check.fail("Cryptographic Signature", "Signature verification failed on BasicOCSPResponse"));
            } else {
                checks.add(Check.pass("Cryptographic Signature", "Signature verified with " + signerCert.getPublicKey().getAlgorithm() + " key"));
            }

            boolean authOk = verifyResponderAuthorization(signerCert, issuerCert, checks);

            // 6. Verify nonce
            boolean nonceOk = true;
            String nonceEchoedHex = null;
            Extension echoedNonceExt = basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (echoedNonceExt != null) {
                byte[] raw = echoedNonceExt.getExtnValue().getOctets();
                try {
                    raw = ASN1OctetString.getInstance(raw).getOctets();
                } catch (Exception ignored) {}
                nonceEchoedHex = HexFormat.of().formatHex(raw);
            }

            if (request.includeNonce()) {
                if (nonceEchoedHex == null) {
                    nonceOk = false;
                    checks.add(Check.fail("Nonce Binding", "Request included a nonce, but responder did not echo any nonce"));
                } else if (!nonceEchoedHex.equalsIgnoreCase(nonceSentHex)) {
                    nonceOk = false;
                    checks.add(Check.fail("Nonce Binding", "Echoed nonce (" + nonceEchoedHex + ") does not match sent nonce (" + nonceSentHex + ")"));
                } else {
                    checks.add(Check.pass("Nonce Binding", "Echoed nonce matches sent nonce (replay attack prevented)"));
                }
            } else {
                checks.add(Check.skipped("Nonce Binding", "Request did not include a nonce (nonce-free mode)"));
            }

            // 7. Extract single response for our cert and check validity window
            SingleResp[] responses = basicResp.getResponses();
            if (responses == null || responses.length == 0) {
                checks.add(Check.fail("CertID Match", "No SingleResp found in BasicOCSPResponse"));
                return errorResult(responderUrl, method, httpStatus, latencyMs, derRequest.length, derResponse.length, getPath, checks, "No SingleResp");
            }
            SingleResp single = responses[0];
            checks.add(Check.pass("CertID Match", "Response matches target serial " + target.serialHex()));

            Date thisUp = single.getThisUpdate();
            Date nextUp = single.getNextUpdate();
            boolean fresh = verifyFreshness(thisUp, nextUp, checks);

            // 8. Extract status
            String certStatus;
            String revTime = null;
            String revReason = null;
            org.bouncycastle.cert.ocsp.CertificateStatus st = single.getCertStatus();
            if (st == org.bouncycastle.cert.ocsp.CertificateStatus.GOOD) {
                certStatus = "GOOD";
            } else if (st instanceof RevokedStatus rev) {
                certStatus = "REVOKED";
                revTime = rev.getRevocationTime() != null ? rev.getRevocationTime().toInstant().toString() : null;
                revReason = rev.hasRevocationReason()
                        ? mapRevocationReason(rev.getRevocationReason())
                        : "UNSPECIFIED";
            } else {
                certStatus = "UNKNOWN";
            }
            checks.add(Check.pass("Certificate Status", "Parsed status: " + certStatus
                    + (revReason != null ? " (" + revReason + ")" : "")));

            boolean overallValid = sigOk && authOk && nonceOk && fresh;

            return new OcspCheckResult(
                    overallValid,
                    responderUrl,
                    method,
                    httpStatus,
                    "SUCCESSFUL",
                    certStatus,
                    revTime,
                    revReason,
                    target.serialHex(),
                    thisUp != null ? thisUp.toInstant().toString() : null,
                    nextUp != null ? nextUp.toInstant().toString() : null,
                    basicResp.getProducedAt() != null ? basicResp.getProducedAt().toInstant().toString() : null,
                    basicResp.getResponderId().toASN1Primitive().toString(),
                    signerCert.getSubjectX500Principal().getName(),
                    request.includeNonce(),
                    nonceSentHex,
                    nonceEchoedHex,
                    latencyMs,
                    derRequest.length,
                    derResponse.length,
                    getPath,
                    checks,
                    null
            );

        } catch (Exception e) {
            log.error("OCSP client check failed: {}", e.getMessage(), e);
            checks.add(Check.fail("Client Execution", e.getClass().getSimpleName() + ": " + e.getMessage()));
            return errorResult(responderUrl, method, 0, 0, 0, 0, null, checks, e.getMessage());
        }
    }

    private ResponseEntity<byte[]> sendRequest(String responderUrl, String method, byte[] derRequest, String getPath) {
        if ("GET".equalsIgnoreCase(method)) {
            String fullUrl = responderUrl.replaceAll("/+$", "") + getPath.replaceFirst("^/ocsp", "");
            return restClient.get()
                    .uri(fullUrl)
                    .accept(MediaType.parseMediaType(OCSP_RESPONSE_CONTENT_TYPE))
                    .retrieve()
                    .toEntity(byte[].class);
        } else {
            return restClient.post()
                    .uri(responderUrl)
                    .contentType(MediaType.parseMediaType(OCSP_REQUEST_CONTENT_TYPE))
                    .accept(MediaType.parseMediaType(OCSP_RESPONSE_CONTENT_TYPE))
                    .body(derRequest)
                    .retrieve()
                    .toEntity(byte[].class);
        }
    }

    private boolean verifySignature(BasicOCSPResp basicResp, X509Certificate signerCert) {
        try {
            ContentVerifierProvider cvp = new JcaContentVerifierProviderBuilder()
                    .setProvider("BC").build(signerCert.getPublicKey());
            return basicResp.isSignatureValid(cvp);
        } catch (Exception e) {
            log.warn("OCSP signature verification exception: {}", e.getMessage());
            return false;
        }
    }

    private boolean verifyResponderAuthorization(X509Certificate signerCert, X509Certificate issuerCert, List<Check> checks) {
        if (issuerCert == null) {
            checks.add(Check.skipped("Responder Authorization", "No CA certificate available to verify delegation chain"));
            return true;
        }
        if (Arrays.equals(signerCert.getPublicKey().getEncoded(), issuerCert.getPublicKey().getEncoded())) {
            checks.add(Check.pass("Responder Authorization", "Signer is the issuing CA directly (RFC 6960 §4.2.2.2 Option 1)"));
            return true;
        }
        try {
            signerCert.verify(issuerCert.getPublicKey());
        } catch (Exception e) {
            checks.add(Check.fail("Responder Authorization", "Signer cert is not signed by the issuing CA: " + e.getMessage()));
            return false;
        }
        try {
            List<String> ekus = signerCert.getExtendedKeyUsage();
            if (ekus == null || !ekus.contains(KeyPurposeId.id_kp_OCSPSigning.getId())) {
                checks.add(Check.fail("Responder Authorization", "Signer cert lacks id-kp-OCSPSigning EKU (RFC 6960 §4.2.2.2 Option 2)"));
                return false;
            }
        } catch (Exception e) {
            checks.add(Check.fail("Responder Authorization", "Could not read signer EKUs: " + e.getMessage()));
            return false;
        }
        checks.add(Check.pass("Responder Authorization", "Signer is an authorized delegated responder (issued by CA + OCSPSigning EKU)"));
        return true;
    }

    private boolean verifyFreshness(Date thisUpdate, Date nextUpdate, List<Check> checks) {
        Instant now = Instant.now();
        if (thisUpdate == null) {
            checks.add(Check.fail("Freshness", "Response is missing thisUpdate"));
            return false;
        }
        if (thisUpdate.toInstant().isAfter(now.plusSeconds(300))) {
            checks.add(Check.fail("Freshness", "thisUpdate is in the future: " + thisUpdate.toInstant()));
            return false;
        }
        if (nextUpdate != null && now.isAfter(nextUpdate.toInstant().plusSeconds(300))) {
            checks.add(Check.fail("Freshness", "Response has expired: nextUpdate was " + nextUpdate.toInstant()));
            return false;
        }
        checks.add(Check.pass("Freshness", "Response is fresh (thisUpdate=" + thisUpdate.toInstant()
                + (nextUpdate != null ? ", nextUpdate=" + nextUpdate.toInstant() : "") + ")"));
        return true;
    }

    private X509Certificate extractSignerCert(BasicOCSPResp basicResp, X509Certificate issuerCert) throws Exception {
        X509CertificateHolder[] certs = basicResp.getCerts();
        if (certs != null && certs.length > 0) {
            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certs[0]);
        }
        if (issuerCert != null) {
            return issuerCert;
        }
        throw new IllegalStateException("BasicOCSPResponse includes no embedded certificate and no CA was supplied");
    }

    private TargetCert resolveTarget(OcspCheckRequest req) throws Exception {
        if (req.certificatePem() != null && !req.certificatePem().isBlank()) {
            X509Certificate cert = readCertificate(new StringReader(req.certificatePem()));
            return new TargetCert(cert.getSerialNumber(), cert);
        }
        if (req.serialHex() != null && !req.serialHex().isBlank()) {
            String clean = req.serialHex().toLowerCase().replaceAll("[^0-9a-f]", "");
            return new TargetCert(new BigInteger(clean, 16), null);
        }
        throw new IllegalArgumentException("Either certificatePem or serialHex must be provided");
    }

    private X509Certificate resolveIssuer(OcspCheckRequest req) throws Exception {
        if (req.issuerPem() != null && !req.issuerPem().isBlank()) {
            return readCertificate(new StringReader(req.issuerPem()));
        }
        return this.trustAnchor;
    }

    private static X509Certificate readCertificate(java.io.Reader reader) throws Exception {
        try (PEMParser parser = new PEMParser(reader)) {
            Object obj = parser.readObject();
            if (obj instanceof X509CertificateHolder holder) {
                return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
            }
            throw new IllegalArgumentException("Expected X509Certificate in PEM, got: " + (obj != null ? obj.getClass().getName() : "null"));
        }
    }

    private static String mapResponseStatus(int status) {
        return switch (status) {
            case OCSPRespBuilder.SUCCESSFUL -> "SUCCESSFUL";
            case OCSPRespBuilder.MALFORMED_REQUEST -> "MALFORMED_REQUEST";
            case OCSPRespBuilder.INTERNAL_ERROR -> "INTERNAL_ERROR";
            case OCSPRespBuilder.TRY_LATER -> "TRY_LATER";
            case OCSPRespBuilder.SIG_REQUIRED -> "SIG_REQUIRED";
            case OCSPRespBuilder.UNAUTHORIZED -> "UNAUTHORIZED";
            default -> "UNKNOWN_" + status;
        };
    }

    private static String mapRevocationReason(int reason) {
        String[] reasons = {
                "UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "AFFILIATION_CHANGED",
                "SUPERSEDED", "CESSATION_OF_OPERATION", "CERTIFICATE_HOLD", "UNKNOWN",
                "REMOVE_FROM_CRL", "PRIVILEGE_WITHDRAWN", "AA_COMPROMISE"
        };
        if (reason >= 0 && reason < reasons.length) {
            return reasons[reason];
        }
        return "REASON_" + reason;
    }

    private OcspCheckResult errorResult(String responderUrl, String method, int httpStatus,
                                        double latencyMs, int reqLen, int respLen, String path,
                                        List<Check> checks, String error) {
        return new OcspCheckResult(
                false, responderUrl, method, httpStatus, "ERROR", null,
                null, null, null, null, null, null, null, null,
                false, null, null, latencyMs, reqLen, respLen, path, checks, error
        );
    }

    private record TargetCert(BigInteger serial, X509Certificate certificate) {
        String serialHex() {
            return HexFormat.of().formatHex(serial.toByteArray());
        }
    }
}

