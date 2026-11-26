package lu.incert.ocsp.signing.provider;

import lu.incert.ocsp.signing.pkcs11.Pkcs11Constants;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Engine;
import lu.incert.ocsp.signing.pkcs11.TokenInfo;
import lu.incert.ocsp.signing.port.CryptoDeviceSpec;
import lu.incert.ocsp.signing.port.CryptoProviderPort;
import lu.incert.ocsp.signing.port.DiscoveredSlotInfo;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * {@link CryptoDeviceAdapterFactory} creating in-process {@code PKCS11J} adapters backed by
 * {@code org.xipki:ipkcs11wrapper} and {@link LibraryPathAllowlist}.
 */
@Component
public class Pkcs11jDeviceAdapterFactory implements CryptoDeviceAdapterFactory {

    private final Pkcs11Engine pkcs11Engine;
    private final LibraryPathAllowlist allowlist;

    public Pkcs11jDeviceAdapterFactory(
            @Qualifier("pkcs11Engine") Pkcs11Engine pkcs11Engine,
            LibraryPathAllowlist allowlist) {
        this.pkcs11Engine = pkcs11Engine;
        this.allowlist = allowlist;
    }

    @Override
    public boolean supports(String wrapperType) {
        return wrapperType == null || wrapperType.isBlank() || "PKCS11J".equalsIgnoreCase(wrapperType.trim());
    }

    @Override
    public CryptoProviderPort create(CryptoDeviceSpec spec) {
        return new Pkcs11jCryptoProviderAdapter(spec, pkcs11Engine, allowlist);
    }

    @Override
    public List<DiscoveredSlotInfo> discoverSlots(String libraryPath, String libraryWrapperPath) {
        String safeLib = allowlist.validateLibraryPath(libraryPath);
        String safeWrapper = allowlist.validateWrapperPath(libraryWrapperPath);
        List<TokenInfo> raw = pkcs11Engine.discoverSlots(safeLib, safeWrapper);
        List<DiscoveredSlotInfo> out = new ArrayList<>(raw.size());
        for (int i = 0; i < raw.size(); i++) {
            TokenInfo info = raw.get(i);
            boolean initialized = (info.flags() & Pkcs11Constants.CKF_TOKEN_INITIALIZED) != 0L;
            out.add(new DiscoveredSlotInfo(
                    info.slotId(),
                    i,
                    info.label(),
                    info.manufacturerId(),
                    info.model(),
                    info.serialNumber(),
                    initialized,
                    info.flags()
            ));
        }
        return out;
    }

    @Override
    public DiscoveredSlotInfo initializeToken(
            String libraryPath,
            String libraryWrapperPath,
            Long slotId,
            String tokenLabel,
            char[] soPin,
            char[] userPin) {
        String safeLib = allowlist.validateLibraryPath(libraryPath);
        String safeWrapper = allowlist.validateWrapperPath(libraryWrapperPath);
        TokenInfo info = pkcs11Engine.initToken(safeLib, safeWrapper, slotId, tokenLabel, soPin, userPin);

        // Determine updated slotListIndex for the newly initialized token
        List<TokenInfo> allSlots = pkcs11Engine.discoverSlots(safeLib, safeWrapper);
        int slotIdx = 0;
        for (int i = 0; i < allSlots.size(); i++) {
            if (allSlots.get(i).slotId() == info.slotId()) {
                slotIdx = i;
                break;
            }
        }
        boolean initialized = (info.flags() & Pkcs11Constants.CKF_TOKEN_INITIALIZED) != 0L;
        return new DiscoveredSlotInfo(
                info.slotId(),
                slotIdx,
                info.label(),
                info.manufacturerId(),
                info.model(),
                info.serialNumber(),
                initialized,
                info.flags()
        );
    }
}
