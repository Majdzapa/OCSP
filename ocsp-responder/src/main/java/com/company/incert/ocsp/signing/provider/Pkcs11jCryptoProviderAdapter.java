package com.company.incert.ocsp.signing.provider;

import com.company.incert.ocsp.signing.pkcs11.KeyMetadata;
import com.company.incert.ocsp.signing.pkcs11.Pkcs11Engine;
import com.company.incert.ocsp.signing.pkcs11.Pkcs11Exception;
import com.company.incert.ocsp.signing.pkcs11.Pkcs11Provider;
import com.company.incert.ocsp.signing.pkcs11.Pkcs11ProviderConfig;
import com.company.incert.ocsp.signing.port.ActivatableCryptoProvider;
import com.company.incert.ocsp.signing.port.CryptoDeviceSpec;
import com.company.incert.ocsp.signing.port.CryptoProviderPort;
import com.company.incert.ocsp.signing.port.DeviceActivationState;
import com.company.incert.ocsp.signing.port.DeviceLockedException;
import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * In-process {@link CryptoProviderPort} + {@link ActivatableCryptoProvider} backed directly by
 * {@code org.xipki:ipkcs11wrapper} ({@link Pkcs11Engine}).
 * <p>
 * Pattern 2 (Runtime Activation): starts in {@link DeviceActivationState#LOCKED}, unlocks in memory
 * on {@link #activate(char[])} with immediate PIN wiping after {@code C_Login}, and flips cleanly
 * back to {@code LOCKED} on {@link #deactivate()} or token logout ({@code CKR_USER_NOT_LOGGED_IN}).
 */
public final class Pkcs11jCryptoProviderAdapter implements CryptoProviderPort, ActivatableCryptoProvider {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11jCryptoProviderAdapter.class);
    public static final String PROVIDER_TYPE = "PKCS11J";

    private final CryptoDeviceSpec spec;
    private final Pkcs11Engine pkcs11Engine;
    private final LibraryPathAllowlist allowlist;

    private volatile Pkcs11Provider activeProvider;
    private volatile DeviceActivationState state = DeviceActivationState.LOCKED;
    private volatile String statusMessage = "LOCKED — awaiting runtime PIN unlock";
    private volatile long resolvedSlotId;
    private volatile String resolvedTokenLabel;

    public Pkcs11jCryptoProviderAdapter(
            CryptoDeviceSpec spec,
            Pkcs11Engine pkcs11Engine,
            LibraryPathAllowlist allowlist) {
        this.spec = spec;
        this.pkcs11Engine = pkcs11Engine;
        this.allowlist = allowlist;
        this.resolvedSlotId = spec.slotId() != null ? spec.slotId() : spec.slotListIndex();
        this.resolvedTokenLabel = spec.tokenLabel() != null ? spec.tokenLabel() : "";
    }

    @Override
    public String providerId() {
        return spec.deviceId();
    }

    @Override
    public String providerType() {
        return PROVIDER_TYPE;
    }

    @Override
    public DeviceActivationState activationState() {
        return state;
    }

    @Override
    public synchronized void activate(char[] pin) {
        try {
            if (pin == null || pin.length == 0) {
                throw new IllegalArgumentException("HSM PIN is required to unlock device '" + spec.deviceId() + "'");
            }
            if (state == DeviceActivationState.ACTIVE && activeProvider != null) {
                return;
            }
            String safeLibrary = allowlist.validateLibraryPath(spec.libraryPath());
            String safeWrapper = allowlist.validateWrapperPath(spec.libraryWrapperPath());

            Pkcs11ProviderConfig cfg = new Pkcs11ProviderConfig(
                    spec.deviceId(),
                    safeLibrary,
                    safeWrapper,
                    spec.tokenLabel(),
                    spec.slotId(),
                    spec.slotListIndex(),
                    pin,
                    spec.poolSize(),
                    spec.prehashInJvm()
            );

            Pkcs11Provider registered = pkcs11Engine.register(cfg, this::handleSessionLoggedOut);
            this.activeProvider = registered;
            this.resolvedSlotId = registered.getSlotId();
            this.resolvedTokenLabel = registered.getTokenLabel();
            this.state = DeviceActivationState.ACTIVE;
            this.statusMessage = "ACTIVE (slotId=" + resolvedSlotId + ", token=" + resolvedTokenLabel + ")";
            log.info("Unlocked HSM device '{}' via ipkcs11wrapper (slotId={}, token={})",
                    spec.deviceId(), resolvedSlotId, resolvedTokenLabel);
        } catch (RuntimeException e) {
            pkcs11Engine.unregister(spec.deviceId());
            this.activeProvider = null;
            this.state = DeviceActivationState.LOCKED;
            this.statusMessage = "LOCKED (unlock failed: " + e.getMessage() + ")";
            if (e instanceof IllegalArgumentException) {
                throw e;
            }
            throw new IllegalStateException(
                    "Failed to unlock HSM device '" + spec.deviceId() + "': " + e.getMessage(), e);
        } finally {
            if (pin != null) {
                Arrays.fill(pin, '\0');
            }
        }
    }

    @Override
    public synchronized void deactivate() {
        this.activeProvider = null;
        pkcs11Engine.unregister(spec.deviceId());
        this.state = DeviceActivationState.LOCKED;
        this.statusMessage = "LOCKED — locked by administrator";
        log.info("Locked HSM device '{}' (C_Logout / session pool closed)", spec.deviceId());
    }

    private synchronized void handleSessionLoggedOut() {
        this.activeProvider = null;
        pkcs11Engine.unregister(spec.deviceId());
        this.state = DeviceActivationState.LOCKED;
        this.statusMessage = "LOCKED — HSM session logged out; re-activation required";
        log.warn("HSM device '{}' session logged out; transitioned back to LOCKED", spec.deviceId());
    }

    @Override
    public ProviderDeviceInfo getDeviceInfo() {
        Pkcs11Provider provider = this.activeProvider;
        if (state != DeviceActivationState.ACTIVE || provider == null) {
            return new ProviderDeviceInfo(
                    spec.deviceId(),
                    PROVIDER_TYPE,
                    spec.libraryPath(),
                    spec.libraryWrapperPath(),
                    resolvedTokenLabel,
                    resolvedSlotId,
                    state.name(),
                    false,
                    statusMessage,
                    List.of(),
                    Map.of()
            );
        }
        try {
            List<KeyMetadata> keys = provider.listKeys();
            List<String> labels = keys.stream().map(KeyMetadata::keyLabel).distinct().toList();
            Map<String, String> algs = new LinkedHashMap<>();
            keys.forEach(k -> algs.putIfAbsent(k.keyLabel(), k.keyAlgorithm()));
            return new ProviderDeviceInfo(
                    spec.deviceId(),
                    PROVIDER_TYPE,
                    spec.libraryPath(),
                    spec.libraryWrapperPath(),
                    resolvedTokenLabel,
                    resolvedSlotId,
                    DeviceActivationState.ACTIVE.name(),
                    true,
                    statusMessage,
                    labels,
                    algs
            );
        } catch (Pkcs11Exception e) {
            if (e.isNotLoggedIn()) {
                handleSessionLoggedOut();
                return getDeviceInfo();
            }
            return new ProviderDeviceInfo(
                    spec.deviceId(),
                    PROVIDER_TYPE,
                    spec.libraryPath(),
                    spec.libraryWrapperPath(),
                    resolvedTokenLabel,
                    resolvedSlotId,
                    DeviceActivationState.ERROR.name(),
                    false,
                    "ERROR: " + e.getMessage(),
                    List.of(),
                    Map.of()
            );
        } catch (RuntimeException e) {
            return new ProviderDeviceInfo(
                    spec.deviceId(),
                    PROVIDER_TYPE,
                    spec.libraryPath(),
                    spec.libraryWrapperPath(),
                    resolvedTokenLabel,
                    resolvedSlotId,
                    DeviceActivationState.ERROR.name(),
                    false,
                    "ERROR: " + e.getMessage(),
                    List.of(),
                    Map.of()
            );
        }
    }

    @Override
    public List<String> listKeyLabels() {
        Pkcs11Provider provider = requireActive();
        try {
            return provider.listKeyLabels();
        } catch (Pkcs11Exception e) {
            throw translatePkcs11Exception(e);
        }
    }

    @Override
    public Map<String, String> getKeyAlgorithms() {
        Pkcs11Provider provider = requireActive();
        try {
            Map<String, String> out = new LinkedHashMap<>();
            for (KeyMetadata km : provider.listKeys()) {
                out.putIfAbsent(km.keyLabel(), km.keyAlgorithm());
            }
            return out;
        } catch (Pkcs11Exception e) {
            throw translatePkcs11Exception(e);
        }
    }

    @Override
    public String generateCsr(
            String keyLabel,
            String subjectDn,
            String keyAlgorithm,
            int keySize,
            boolean reuseExistingKey) {
        Pkcs11Provider provider = requireActive();
        try {
            return provider.generateCsr(keyLabel, subjectDn, keyAlgorithm, keySize, reuseExistingKey);
        } catch (Pkcs11Exception e) {
            throw translatePkcs11Exception(e);
        }
    }

    @Override
    public void importCertificate(String keyLabel, X509CertificateHolder certificate) {
        Pkcs11Provider provider = requireActive();
        try {
            provider.importCertificate(keyLabel, certificate);
        } catch (Pkcs11Exception e) {
            throw translatePkcs11Exception(e);
        }
    }

    @Override
    public byte[] sign(String keyLabel, String signatureAlgorithm, byte[] data) {
        Pkcs11Provider provider = requireActive();
        try {
            return provider.sign(keyLabel, signatureAlgorithm, data);
        } catch (Pkcs11Exception e) {
            throw translatePkcs11Exception(e);
        }
    }

    @Override
    public ContentSigner createContentSigner(String keyLabel, String signatureAlgorithm) {
        requireActive();
        return CryptoProviderPort.super.createContentSigner(keyLabel, signatureAlgorithm);
    }

    @Override
    public void close() {
        deactivate();
    }

    private Pkcs11Provider requireActive() {
        Pkcs11Provider provider = this.activeProvider;
        if (state != DeviceActivationState.ACTIVE || provider == null) {
            throw new DeviceLockedException(
                    "Crypto device '" + spec.deviceId() + "' is LOCKED — unlock it with the HSM PIN first");
        }
        return provider;
    }

    private RuntimeException translatePkcs11Exception(Pkcs11Exception e) {
        if (e.isNotLoggedIn()) {
            handleSessionLoggedOut();
            return new DeviceLockedException(
                    "Crypto device '" + spec.deviceId() + "' logged out (" + e.getMessage() + ") — re-activation required");
        }
        return new IllegalStateException("PKCS#11 error on device '" + spec.deviceId() + "': " + e.getMessage(), e);
    }
}

