package com.company.incert.pkcs11j.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.io.StringWriter;

/**
 * Builds and PEM-encodes PKCS#10 Certificate Signing Requests using a caller-provided {@link ContentSigner}.
 */
public final class Pkcs11CsrGenerator {

    private Pkcs11CsrGenerator() {}

    public static String generatePem(String subjectDn, SubjectPublicKeyInfo spki, ContentSigner contentSigner) {
        try {
            PKCS10CertificationRequest csr = new PKCS10CertificationRequestBuilder(new X500Name(subjectDn), spki)
                    .build(contentSigner);
            try (StringWriter sw = new StringWriter(); JcaPEMWriter pw = new JcaPEMWriter(sw)) {
                pw.writeObject(csr);
                pw.flush();
                return sw.toString();
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build PKCS#10 CSR: " + e.getMessage(), e);
        }
    }
}

