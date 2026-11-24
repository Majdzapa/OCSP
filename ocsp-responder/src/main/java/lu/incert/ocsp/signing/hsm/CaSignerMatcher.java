package lu.incert.ocsp.signing.hsm;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
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
            return new MatchedSigner<>(
                    target,
                    new X509CertificateHolder[]{holder},
                    alg,
                    holder.getNotAfter().toInstant(),
                    holder.getIssuer().getEncoded(),
                    extractAuthorityKeyId(holder),
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
            if (!Arrays.equals(md.digest(entry.issuerEncoded()), reqIssuerNameHash)) {
                continue;
            }
            int score = 1; // Issuer DN matched
            if (entry.authorityKeyId() != null && OIWObjectIdentifiers.idSHA1.equals(hashAlgOid)) {
                if (Arrays.equals(entry.authorityKeyId(), reqIssuerKeyHash)) {
                    score = 3; // Issuer DN + AuthorityKeyIdentifier matched
                } else {
                    continue; // Different CA key under same DN
                }
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

