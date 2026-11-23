package com.company.incert.ocsp.signing.pkcs11;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * BouncyCastle {@link ContentSigner} backed by a {@link Pkcs11Provider} slot/key.
 */
public final class Pkcs11ContentSigner implements ContentSigner {

    private static final DefaultSignatureAlgorithmIdentifierFinder ALG_FINDER =
            new DefaultSignatureAlgorithmIdentifierFinder();

    private final Pkcs11Provider provider;
    private final String keyLabel;
    private final String signatureAlgorithm;
    private final AlgorithmIdentifier algorithmIdentifier;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream(2048);

    public Pkcs11ContentSigner(Pkcs11Provider provider, String keyLabel, String signatureAlgorithm) {
        this.provider = provider;
        this.keyLabel = keyLabel;
        this.signatureAlgorithm = signatureAlgorithm;
        this.algorithmIdentifier = ALG_FINDER.find(signatureAlgorithm);
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
        return provider.sign(keyLabel, signatureAlgorithm, buffer.toByteArray());
    }
}

