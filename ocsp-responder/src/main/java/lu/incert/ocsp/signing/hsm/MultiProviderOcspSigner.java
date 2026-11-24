package lu.incert.ocsp.signing.hsm;

import lu.incert.ocsp.signing.port.CryptoProviderPort;
import lu.incert.ocsp.signing.port.DeviceLockedException;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import lu.incert.ocsp.signing.provider.PkcsProviders;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.operator.ContentSigner;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Multi-device {@link OcspSigner} delegating cryptographic operations to {@link PkcsProviders}
 * and CA-specific certificate matching to {@link CaSignerMatcher}.
 */
@Slf4j
public class MultiProviderOcspSigner implements OcspSigner {

    private final PkcsProviders pkcsProviders;
    private volatile String activeProviderId;
    private volatile String activeKeyLabel;

    private final AtomicReference<DefaultSignerState> stateRef = new AtomicReference<>();
    private final List<CaSignerMatcher.MatchedSigner<ProviderKeyRef>> registeredSigners = new CopyOnWriteArrayList<>();

    public MultiProviderOcspSigner(PkcsProviders pkcsProviders, String defaultKeyLabel) {
        this.pkcsProviders = pkcsProviders;
        this.activeProviderId = pkcsProviders.getDefaultProviderId();
        this.activeKeyLabel = defaultKeyLabel != null && !defaultKeyLabel.isBlank()
                ? defaultKeyLabel.trim()
                : "ocsp-signing-key";
    }

    @Override
    public ContentSigner createContentSigner() {
        DefaultSignerState state = requireState();
        return pkcsProviders.getProvider(state.target().providerId())
                .createContentSigner(state.target().keyLabel(), state.algorithm());
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
        if (pkcsProviders.listProviderIds().isEmpty()) {
            return "PKCS11J";
        }
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
        if (pkcsProviders.listProviderIds().isEmpty()) {
            return List.of();
        }
        try {
            return pkcsProviders.getDefaultProvider().listKeyLabels();
        } catch (DeviceLockedException e) {
            return List.of();
        }
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
    public String generateCsr(
            String providerId,
            String keyLabel,
            String subjectDn,
            String keyAlgorithm,
            int keySize,
            boolean reuseExistingKey) {
        return pkcsProviders.getProvider(providerId)
                .generateCsr(keyLabel, subjectDn, keyAlgorithm, keySize, reuseExistingKey);
    }

    @Override
    public void importCertificateToToken(String providerId, String keyLabel, X509CertificateHolder certificate) {
        if (keyLabel == null || keyLabel.isBlank() || certificate == null) {
            return;
        }
        pkcsProviders.getProvider(providerId).importCertificate(keyLabel.trim(), certificate);
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
                : CaSignerMatcher.detectSignatureAlgorithm(certificate);

        stateRef.set(new DefaultSignerState(
                new ProviderKeyRef(resolvedProviderId, this.activeKeyLabel),
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
        List<CaSignerMatcher.MatchedSigner<ProviderKeyRef>> updated = new ArrayList<>();
        Instant now = Instant.now();
        for (RegisteredSigner rs : signers) {
            try {
                X509CertificateHolder holder = rs.certificate();
                if (holder == null || now.isAfter(holder.getNotAfter().toInstant())) {
                    continue;
                }
                CryptoProviderPort port = pkcsProviders.getProvider(rs.providerId());
                updated.add(CaSignerMatcher.MatchedSigner.of(
                        new ProviderKeyRef(port.providerId(), rs.keyLabel()),
                        holder,
                        rs.signatureAlgorithm(),
                        rs.preferred()));
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
        CaSignerMatcher.MatchedSigner<ProviderKeyRef> selected =
                CaSignerMatcher.selectBest(registeredSigners, certId).orElse(null);
        if (selected != null) {
            ProviderKeyRef ref = selected.target();
            ContentSigner cs = pkcsProviders.getProvider(ref.providerId())
                    .createContentSigner(ref.keyLabel(), selected.algorithm());
            return new SigningSelection(selected.chain(), cs);
        }

        DefaultSignerState fallback = requireState();
        ContentSigner cs = pkcsProviders.getProvider(fallback.target().providerId())
                .createContentSigner(fallback.target().keyLabel(), fallback.algorithm());
        return new SigningSelection(fallback.chain(), cs);
    }

    private DefaultSignerState requireState() {
        DefaultSignerState state = stateRef.get();
        if (state == null) {
            throw new IllegalStateException("No active signing certificate initialized");
        }
        return state;
    }

    private record ProviderKeyRef(String providerId, String keyLabel) {}

    private record DefaultSignerState(
            ProviderKeyRef target,
            X509CertificateHolder[] chain,
            String algorithm,
            Instant notAfter
    ) {}
}
