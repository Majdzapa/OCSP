package com.company.incert.ocsp.signing.hsm;

import com.company.incert.ocsp.signing.port.CryptoProviderPort;
import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
import com.company.incert.ocsp.signing.provider.PkcsProviders;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.operator.ContentSigner;

import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Multi-device {@link OcspSigner} delegating all hardware/token operations to {@link PkcsProviders}.
 * Supports multiple concurrent signing devices (PKCS11J over gRPC, local SunPKCS11, etc.) and
 * automatically selects the matching issuing CA's signing certificate and target device per OCSP request.
 */
@Slf4j
public class MultiProviderOcspSigner implements OcspSigner {

    private final PkcsProviders pkcsProviders;
    private volatile String activeProviderId;
    private volatile String activeKeyLabel;

    private final AtomicReference<DefaultSignerState> stateRef = new AtomicReference<>();
    private final List<RegisteredSignerEntry> registeredSigners = new CopyOnWriteArrayList<>();

    public MultiProviderOcspSigner(PkcsProviders pkcsProviders, String defaultKeyLabel) {
        this.pkcsProviders = pkcsProviders;
        this.activeProviderId = pkcsProviders.getDefaultProviderId();
        this.activeKeyLabel = defaultKeyLabel != null && !defaultKeyLabel.isBlank()
                ? defaultKeyLabel.trim()
                : "ocsp-signing-key";
    }

    @Override
    public ContentSigner createContentSigner() throws Exception {
        DefaultSignerState state = requireState();
        return pkcsProviders.getProvider(state.providerId())
                .createContentSigner(state.keyLabel(), state.algorithm());
    }

    @Override
    public X509CertificateHolder[] getSignerChain() {
        return requireState().chain();
    }

    @Override
    public long signingCertDaysUntilExpiry() {
        DefaultSignerState state = stateRef.get();
        if (state == null || registeredSigners.isEmpty()) {
            return -1;
        }
        return ChronoUnit.DAYS.between(Instant.now(), state.notAfter());
    }

    @Override
    public String type() {
        return pkcsProviders.getDefaultProvider().providerType();
    }

    @Override
    public String getDefaultProviderId() {
        return pkcsProviders.getDefaultProviderId();
    }

    @Override
    public List<ProviderDeviceInfo> listProviders() {
        return pkcsProviders.listProviders();
    }

    @Override
    public String getActiveKeyLabel() {
        return activeKeyLabel;
    }

    public String getActiveProviderId() {
        return activeProviderId;
    }

    @Override
    public List<String> listKeyLabels() {
        return pkcsProviders.getDefaultProvider().listKeyLabels();
    }

    @Override
    public List<String> listKeyLabels(String providerId) {
        return pkcsProviders.getProvider(providerId).listKeyLabels();
    }

    @Override
    public Map<String, String> getKeyAlgorithms() {
        Map<String, String> merged = new LinkedHashMap<>();
        for (ProviderDeviceInfo info : pkcsProviders.listProviders()) {
            if (info.keyAlgorithms() != null) {
                merged.putAll(info.keyAlgorithms());
            }
        }
        return merged;
    }

    @Override
    public String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
        return generateCsr(null, keyLabel, subjectDn, keyAlgorithm, keySize, reuseExistingKey);
    }

    @Override
    public String generateCsr(
            String providerId,
            String keyLabel,
            String subjectDn,
            String keyAlgorithm,
            int keySize,
            boolean reuseExistingKey) {
        CryptoProviderPort provider = pkcsProviders.getProvider(providerId);
        return provider.generateCsr(keyLabel, subjectDn, keyAlgorithm, keySize, reuseExistingKey);
    }

    @Override
    public void importCertificateToToken(String keyLabel, X509CertificateHolder certificate) {
        importCertificateToToken(null, keyLabel, certificate);
    }

    @Override
    public void importCertificateToToken(String providerId, String keyLabel, X509CertificateHolder certificate) {
        if (keyLabel == null || keyLabel.isBlank() || certificate == null) {
            return;
        }
        CryptoProviderPort provider = pkcsProviders.getProvider(providerId);
        provider.importCertificate(keyLabel.trim(), certificate);
    }

    @Override
    public void updateActiveCertificate(String keyLabel, X509CertificateHolder certificate) {
        updateActiveCertificate(null, keyLabel, certificate, null);
    }

    @Override
    public void updateActiveCertificate(String keyLabel, X509CertificateHolder certificate, String signatureAlgorithm) {
        updateActiveCertificate(null, keyLabel, certificate, signatureAlgorithm);
    }

    @Override
    public synchronized void updateActiveCertificate(
            String providerId,
            String keyLabel,
            X509CertificateHolder certificate,
            String signatureAlgorithm) {
        CryptoProviderPort provider = pkcsProviders.getProvider(providerId);
        String resolvedProviderId = provider.providerId();
        if (keyLabel != null && !keyLabel.isBlank()) {
            this.activeKeyLabel = keyLabel.trim();
        }
        this.activeProviderId = resolvedProviderId;

        if (certificate == null) {
            log.warn("No X.509 certificate passed to updateActiveCertificate for provider='{}', keyLabel='{}'",
                    resolvedProviderId, this.activeKeyLabel);
            return;
        }
        String algorithm = (signatureAlgorithm != null && !signatureAlgorithm.isBlank())
                ? signatureAlgorithm.trim()
                : detectSignatureAlgorithm(certificate);

        stateRef.set(new DefaultSignerState(
                resolvedProviderId,
                this.activeKeyLabel,
                new X509CertificateHolder[]{certificate},
                algorithm,
                certificate.getNotAfter().toInstant()
        ));
        log.info("Active signing certificate updated: provider={} keyLabel={} algorithm={} notAfter={}",
                resolvedProviderId, this.activeKeyLabel, algorithm, certificate.getNotAfter());
    }

    @Override
    public synchronized void syncRegisteredSigners(List<RegisteredSigner> signers) {
        if (signers == null) {
            return;
        }
        List<RegisteredSignerEntry> updated = new ArrayList<>();
        for (RegisteredSigner rs : signers) {
            try {
                X509CertificateHolder holder = rs.certificate();
                if (holder == null || Instant.now().isAfter(holder.getNotAfter().toInstant())) {
                    continue;
                }
                CryptoProviderPort port = pkcsProviders.getProvider(rs.providerId());
                String alg = (rs.signatureAlgorithm() != null && !rs.signatureAlgorithm().isBlank())
                        ? rs.signatureAlgorithm().trim()
                        : detectSignatureAlgorithm(holder);
                byte[] issuerEncoded = holder.getIssuer().getEncoded();
                byte[] aki = extractAuthorityKeyId(holder);
                updated.add(new RegisteredSignerEntry(
                        port.providerId(),
                        rs.keyLabel(),
                        new X509CertificateHolder[]{holder},
                        alg,
                        holder.getNotAfter().toInstant(),
                        issuerEncoded,
                        aki,
                        rs.preferred()
                ));
            } catch (Exception e) {
                log.warn("Failed registering signer (provider='{}', keyLabel='{}'): {}",
                        rs.providerId(), rs.keyLabel(), e.getMessage());
            }
        }
        registeredSigners.clear();
        registeredSigners.addAll(updated);
        log.info("Synchronized {} non-expired signing certificate(s) across PkcsProviders {}",
                registeredSigners.size(), pkcsProviders.listProviderIds());
    }

    @Override
    public SigningSelection selectSigner(CertificateID certId) throws Exception {
        if (registeredSigners.isEmpty()) {
            throw new SignerNotConfiguredException(
                    "No active signing certificate is configured (activate one under Signing Certificates)");
        }
        if (certId != null) {
            Instant now = Instant.now();
            byte[] reqIssuerNameHash = certId.getIssuerNameHash();
            byte[] reqIssuerKeyHash = certId.getIssuerKeyHash();
            ASN1ObjectIdentifier hashAlgOid = certId.getHashAlgOID();
            String digestName = resolveDigestName(hashAlgOid);

            if (digestName != null && reqIssuerNameHash != null) {
                MessageDigest md = MessageDigest.getInstance(digestName);
                RegisteredSignerEntry bestMatch = null;
                int bestScore = -1;

                for (RegisteredSignerEntry entry : registeredSigners) {
                    if (now.isAfter(entry.notAfter())) {
                        continue;
                    }
                    byte[] entryNameHash = md.digest(entry.issuerEncoded());
                    if (!Arrays.equals(entryNameHash, reqIssuerNameHash)) {
                        continue;
                    }

                    int score = 1;
                    if (entry.authorityKeyId() != null && OIWObjectIdentifiers.idSHA1.equals(hashAlgOid)) {
                        if (Arrays.equals(entry.authorityKeyId(), reqIssuerKeyHash)) {
                            score = 3;
                        } else {
                            continue;
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

                if (bestMatch != null) {
                    CryptoProviderPort port = pkcsProviders.getProvider(bestMatch.providerId());
                    ContentSigner cs = port.createContentSigner(bestMatch.keyLabel(), bestMatch.algorithm());
                    return new SigningSelection(bestMatch.chain(), cs);
                }
            }
        }

        DefaultSignerState fallback = requireState();
        CryptoProviderPort port = pkcsProviders.getProvider(fallback.providerId());
        ContentSigner cs = port.createContentSigner(fallback.keyLabel(), fallback.algorithm());
        return new SigningSelection(fallback.chain(), cs);
    }

    private DefaultSignerState requireState() {
        DefaultSignerState state = stateRef.get();
        if (state == null) {
            throw new IllegalStateException("No active signing certificate initialized");
        }
        return state;
    }

    private static String detectSignatureAlgorithm(X509CertificateHolder holder) {
        try {
            if (holder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId().contains("1.2.840.10045")) {
                return "SHA256withECDSA";
            }
        } catch (Exception ignored) {}
        return "SHA256withRSA";
    }

    private static byte[] extractAuthorityKeyId(X509CertificateHolder holder) {
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

    private record DefaultSignerState(
            String providerId,
            String keyLabel,
            X509CertificateHolder[] chain,
            String algorithm,
            Instant notAfter
    ) {}

    private record RegisteredSignerEntry(
            String providerId,
            String keyLabel,
            X509CertificateHolder[] chain,
            String algorithm,
            Instant notAfter,
            byte[] issuerEncoded,
            byte[] authorityKeyId,
            boolean preferred
    ) {}
}

