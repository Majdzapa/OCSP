package com.company.ocsp.responder.service;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * KMS signing façade for the OCSP responder.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Fetches the active OCSP signing certificate and key reference from the KMS
 *       at startup via {@link #refreshSigningCert()}.</li>
 *   <li>Creates a Bouncy Castle {@link ContentSigner} backed by the KMS for each
 *       OCSP response that requires a fresh signature.</li>
 *   <li>Exposes the {@link RespID} and signer certificate chain for embedding in
 *       every OCSP response per RFC 6960 §4.2.2.2.</li>
 * </ul>
 *
 * <p>The signing certificate is cached in-process.  Rotation is supported by
 * calling {@link #refreshSigningCert()} (e.g. triggered by a periodic job or an
 * admin API endpoint) which atomically swaps the cached references with no
 * downtime or request loss.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KmsSigningService {

    private final KmsHttpClient kmsHttpClient;

    /** Atomic reference to the current active signing cert metadata. */
    private final AtomicReference<CachedSignerState> signerStateRef =
            new AtomicReference<>();

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /**
     * Loads the active OCSP signing certificate from the KMS at startup.
     * Throws if the KMS is unreachable — prevents starting a responder that
     * cannot sign.
     */
    @PostConstruct
    public void refreshSigningCert() {
        log.info("Fetching active OCSP signing certificate from KMS...");

        KmsHttpClient.SigningCertResponse resp = kmsHttpClient.getActiveSigningCert();

        List<X509CertificateHolder> chain = parsePemChain(resp.pemChain());
        if (chain.isEmpty()) {
            throw new IllegalStateException("KMS returned an empty signing certificate chain");
        }

        X509CertificateHolder signerCert = chain.get(0);
        RespID respId = new RespID(signerCert.getSubject());

        signerStateRef.set(new CachedSignerState(
            resp.keyReference(),
            resp.algorithm(),
            chain.toArray(new X509CertificateHolder[0]),
            respId
        ));

        log.info("OCSP signing cert loaded. subject={} algorithm={} notAfter={}",
                signerCert.getSubject(),
                resp.algorithm(),
                resp.notAfter());
    }

    // -------------------------------------------------------------------------
    // Public API used by OcspProcessingService
    // -------------------------------------------------------------------------

    /**
     * Creates a {@link ContentSigner} that delegates TBS signing to the KMS.
     * A new instance is created per OCSP response (Bouncy Castle ContentSigner
     * is not reusable — it holds a mutable TBS buffer).
     */
    public ContentSigner createContentSigner() {
        CachedSignerState state = requireState();
        return new KmsBackedContentSigner(kmsHttpClient, state.keyReference(), state.algorithm());
    }

    /**
     * Returns the OCSP responder's {@link RespID} derived from the delegated
     * signing certificate's subject DN (RFC 6960 §4.2.2.3).
     */
    public RespID getOcspSignerNameAsRespId() {
        return requireState().respId();
    }

    /**
     * Returns the full signer certificate chain to embed in OCSP responses
     * (RFC 6960 §4.2.2.2 — enables offline validation without a separate lookup).
     */
    public X509CertificateHolder[] getOcspSignerChain() {
        return requireState().chain();
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private CachedSignerState requireState() {
        CachedSignerState state = signerStateRef.get();
        if (state == null) {
            throw new IllegalStateException(
                    "KMS signing service not yet initialised — call refreshSigningCert() first");
        }
        return state;
    }

    /**
     * Parses a list of PEM-encoded certificate strings into Bouncy Castle holders.
     * The first entry is expected to be the OCSP signing cert (EKU: id-kp-OCSPSigning).
     */
    private List<X509CertificateHolder> parsePemChain(List<String> pemList) {
        List<X509CertificateHolder> result = new ArrayList<>();
        for (String pem : pemList) {
            try (PEMParser parser = new PEMParser(new StringReader(pem))) {
                Object obj = parser.readObject();
                if (obj instanceof X509CertificateHolder holder) {
                    result.add(holder);
                } else {
                    log.warn("Unexpected PEM object type from KMS: {}",
                            obj != null ? obj.getClass().getSimpleName() : "null");
                }
            } catch (IOException e) {
                throw new IllegalStateException("Failed to parse PEM certificate from KMS chain", e);
            }
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Internal state record
    // -------------------------------------------------------------------------

    /** Immutable snapshot of the active OCSP signer state. */
    private record CachedSignerState(
        String                keyReference,
        String                algorithm,
        X509CertificateHolder[] chain,
        RespID                respId
    ) {}
}
