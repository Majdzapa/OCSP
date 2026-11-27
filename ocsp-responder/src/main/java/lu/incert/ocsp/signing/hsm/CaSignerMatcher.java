package lu.incert.ocsp.signing.hsm;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Shared RFC 6960 §4.2.2.2 issuing-CA signer matcher (SRP + DRY).
 * Matches an OCSP request {@link CertificateID} by IssuerNameHash + AuthorityKeyIdentifier across
 * non-expired active signing certificates.
 */
public final class CaSignerMatcher {

    private CaSignerMatcher() {}

    public record MatchedSigner<T>(
            T target,
            X509CertificateHolder[] chain,
            String algorithm,
            Instant notAfter,
            byte[] issuerEncoded,
            byte[] authorityKeyId,
            byte[] subjectEncoded,
            byte[] subjectPublicKeyBits,
            boolean hasOcspSigningEku,
            boolean isCa,
            boolean preferred
    ) {
        public static <T> MatchedSigner<T> of(
                T target,
                X509CertificateHolder holder,
                String requestedAlgorithm,
                boolean preferred) throws IOException {
            String alg = (requestedAlgorithm != null && !requestedAlgorithm.isBlank())
                    ? requestedAlgorithm.trim()
                    : detectSignatureAlgorithm(holder);
            byte[] spkiBits = holder.getSubjectPublicKeyInfo() != null
                    && holder.getSubjectPublicKeyInfo().getPublicKeyData() != null
                    ? holder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()
                    : null;
            return new MatchedSigner<>(
                    target,
                    new X509CertificateHolder[]{holder},
                    alg,
                    holder.getNotAfter().toInstant(),
                    holder.getIssuer().getEncoded(),
                    extractAuthorityKeyId(holder),
                    holder.getSubject().getEncoded(),
                    spkiBits,
                    CaSignerMatcher.hasOcspSigningEku(holder),
                    CaSignerMatcher.isCaCertificate(holder),
                    preferred
            );
        }
    }

    public static <T> Optional<MatchedSigner<T>> selectBest(List<MatchedSigner<T>> candidates, CertificateID certId)
            throws NoSuchAlgorithmException {
        if (candidates == null || candidates.isEmpty() || certId == null) {
            return Optional.empty();
        }
        byte[] reqIssuerNameHash = certId.getIssuerNameHash();
        byte[] reqIssuerKeyHash = certId.getIssuerKeyHash();
        ASN1ObjectIdentifier hashAlgOid = certId.getHashAlgOID();
        String digestName = resolveDigestName(hashAlgOid);
        if (digestName == null || reqIssuerNameHash == null) {
            return Optional.empty();
        }

        Instant now = Instant.now();
        MessageDigest md = MessageDigest.getInstance(digestName);
        MatchedSigner<T> bestMatch = null;
        int bestScore = -1;

        for (MatchedSigner<T> entry : candidates) {
            if (now.isAfter(entry.notAfter())) {
                continue;
            }
            int score = -1;

            // RFC 6960 §4.2.2.2 Case 1: Direct Issuing CA Signer (compare CA public key hash FIRST, then Subject DN)
            if (entry.subjectPublicKeyBits() != null
                    && reqIssuerKeyHash != null
                    && Arrays.equals(md.digest(entry.subjectPublicKeyBits()), reqIssuerKeyHash)
                    && entry.subjectEncoded() != null
                    && Arrays.equals(md.digest(entry.subjectEncoded()), reqIssuerNameHash)) {
                score = 4;
            }
            // RFC 6960 §2.6 / §4.2.2.2 Case 2: Delegated OCSP Signer (requires id-kp-OCSPSigning EKU;
            // compare CA key hash via AKI FIRST when available, then Issuer DN)
            else if (entry.hasOcspSigningEku()) {
                boolean hasSha1Aki = entry.authorityKeyId() != null && OIWObjectIdentifiers.idSHA1.equals(hashAlgOid);
                if (hasSha1Aki && !Arrays.equals(entry.authorityKeyId(), reqIssuerKeyHash)) {
                    continue; // Different CA key (checked before Issuer DN)
                }
                if (entry.issuerEncoded() != null
                        && Arrays.equals(md.digest(entry.issuerEncoded()), reqIssuerNameHash)) {
                    score = hasSha1Aki ? 3 : 1;
                }
            }

            if (score < 0) {
                continue;
            }
            if (entry.preferred()) {
                score += 1;
            }
            if (score > bestScore) {
                bestScore = score;
                bestMatch = entry;
            }
        }
        return Optional.ofNullable(bestMatch);
    }

    /** RFC 6960 §2.6: checks whether the certificate carries the {@code id-kp-OCSPSigning} EKU. */
    public static boolean hasOcspSigningEku(X509CertificateHolder holder) {
        if (holder == null) {
            return false;
        }
        try {
            ExtendedKeyUsage eku = ExtendedKeyUsage.fromExtensions(holder.getExtensions());
            return eku != null && eku.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning);
        } catch (Exception ignored) {
            return false;
        }
    }

    /** Checks whether the certificate is a CA certificate ({@code BasicConstraints cA=true}). */
    public static boolean isCaCertificate(X509CertificateHolder holder) {
        if (holder == null) {
            return false;
        }
        try {
            BasicConstraints bc = BasicConstraints.fromExtensions(holder.getExtensions());
            return bc != null && bc.isCA();
        } catch (Exception ignored) {
            return false;
        }
    }

    /** RFC 6960 §4.2.2.2.1: checks whether the certificate includes {@code id-pkix-ocsp-nocheck}. */
    public static boolean hasOcspNoCheckExtension(X509CertificateHolder holder) {
        if (holder == null) {
            return false;
        }
        return holder.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck) != null;
    }

    public static String detectSignatureAlgorithm(X509CertificateHolder holder) {
        try {
            if (holder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId().contains("1.2.840.10045")) {
                return "SHA256withECDSA";
            }
        } catch (Exception ignored) {}
        return "SHA256withRSA";
    }

    public static byte[] extractAuthorityKeyId(X509CertificateHolder holder) {
        try {
            Extension ext = holder.getExtension(Extension.authorityKeyIdentifier);
            if (ext != null) {
                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(ext.getParsedValue());
                return aki.getKeyIdentifier();
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static String resolveDigestName(ASN1ObjectIdentifier oid) {
        if (OIWObjectIdentifiers.idSHA1.equals(oid)) return "SHA-1";
        if (NISTObjectIdentifiers.id_sha256.equals(oid)) return "SHA-256";
        if (NISTObjectIdentifiers.id_sha384.equals(oid)) return "SHA-384";
        if (NISTObjectIdentifiers.id_sha512.equals(oid)) return "SHA-512";
        return null;
    }
}

