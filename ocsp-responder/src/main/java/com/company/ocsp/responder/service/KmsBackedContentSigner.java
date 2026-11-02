package com.company.ocsp.responder.service;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Base64;
import java.util.Map;

/**
 * Bouncy Castle {@link ContentSigner} that delegates the signing operation to
 * the KMS via the {@link KmsHttpClient} declarative HTTP interface.
 *
 * <h2>How Bouncy Castle uses this class</h2>
 * <ol>
 *   <li>Calls {@link #getOutputStream()} and writes all TBS bytes into it.</li>
 *   <li>Calls {@link #getSignature()} to retrieve the final signature bytes.</li>
 * </ol>
 *
 * <p>At step 2 we encode the buffered TBS bytes as Base64 and POST them to the
 * KMS signing API.  The KMS returns a Base64-encoded DER signature; we decode it
 * and hand it back to Bouncy Castle.  The private key never leaves the HSM.
 *
 * <h2>Algorithm support</h2>
 * The algorithm is determined at construction time from the KMS metadata.
 * Supported values: {@code SHA256withRSA}, {@code SHA384withECDSA}.
 */
@Slf4j
public class KmsBackedContentSigner implements ContentSigner {

    private static final Map<String, AlgorithmIdentifier> ALGORITHM_MAP = Map.of(
        "SHA256withRSA",   new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption),
        "SHA384withRSA",   new AlgorithmIdentifier(PKCSObjectIdentifiers.sha384WithRSAEncryption),
        "SHA512withRSA",   new AlgorithmIdentifier(PKCSObjectIdentifiers.sha512WithRSAEncryption),
        "SHA256withECDSA", new AlgorithmIdentifier(org.bouncycastle.asn1.x9.X9ObjectIdentifiers.ecdsa_with_SHA256),
        "SHA384withECDSA", new AlgorithmIdentifier(org.bouncycastle.asn1.x9.X9ObjectIdentifiers.ecdsa_with_SHA384)
    );

    private final KmsHttpClient kmsHttpClient;
    private final String        keyReference;
    private final String        algorithm;
    private final AlgorithmIdentifier algorithmIdentifier;

    private final ByteArrayOutputStream tbsBuffer = new ByteArrayOutputStream(2048);

    /**
     * @param kmsHttpClient injected declarative HTTP client
     * @param keyReference  opaque KMS key handle (e.g. "ocsp-signing-key-01")
     * @param algorithm     signing algorithm (e.g. "SHA256withRSA")
     */
    public KmsBackedContentSigner(KmsHttpClient kmsHttpClient,
                                   String keyReference,
                                   String algorithm) {
        this.kmsHttpClient      = kmsHttpClient;
        this.keyReference       = keyReference;
        this.algorithm          = algorithm;
        this.algorithmIdentifier = ALGORITHM_MAP.get(algorithm);
        if (this.algorithmIdentifier == null) {
            throw new IllegalArgumentException("Unsupported KMS signing algorithm: " + algorithm);
        }
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    /** Returns a buffer into which Bouncy Castle writes the to-be-signed bytes. */
    @Override
    public OutputStream getOutputStream() {
        return tbsBuffer;
    }

    /**
     * Sends the buffered TBS bytes to the KMS and returns the raw DER signature.
     * Called by Bouncy Castle after all TBS data has been written.
     */
    @Override
    public byte[] getSignature() {
        byte[] tbs       = tbsBuffer.toByteArray();
        String tbsBase64 = Base64.getEncoder().encodeToString(tbs);

        log.debug("Sending {} TBS bytes to KMS for signing (keyRef={}, alg={})",
                tbs.length, keyReference, algorithm);

        KmsHttpClient.SignRequest request = new KmsHttpClient.SignRequest(
                keyReference, tbsBase64, algorithm);

        KmsHttpClient.SignResponse response = kmsHttpClient.sign(request);

        byte[] signature = Base64.getDecoder().decode(response.signature());
        log.debug("KMS signing successful. signature_bytes={}", signature.length);
        return signature;
    }
}
