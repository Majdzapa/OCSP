package com.company.incert.ocsp.signing.port;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Objects;
import java.util.function.Function;

/**
 * Reusable {@link ContentSigner} that buffers TBS bytes and delegates signature generation
 * to a caller-provided signing function (e.g. a stateless gRPC or in-memory signer).
 */
public final class BufferedContentSigner implements ContentSigner {

    private static final DefaultSignatureAlgorithmIdentifierFinder ALG_FINDER =
            new DefaultSignatureAlgorithmIdentifierFinder();

    private final AlgorithmIdentifier algorithmIdentifier;
    private final Function<byte[], byte[]> signFn;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream(2048);

    public BufferedContentSigner(String signatureAlgorithm, Function<byte[], byte[]> signFn) {
        this.algorithmIdentifier = ALG_FINDER.find(signatureAlgorithm);
        this.signFn = Objects.requireNonNull(signFn, "signFn must not be null");
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
        return buffer;
    }

    @Override
    public byte[] getSignature() {
        return signFn.apply(buffer.toByteArray());
    }
}

