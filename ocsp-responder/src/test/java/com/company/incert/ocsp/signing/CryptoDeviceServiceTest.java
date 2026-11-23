package com.company.incert.ocsp.signing;

import com.company.incert.ocsp.signing.dto.CryptoDeviceDto;
import com.company.incert.ocsp.signing.dto.CryptoDeviceRequest;
import com.company.incert.ocsp.signing.dto.CryptoProviderDto;
import com.company.incert.ocsp.signing.dto.CryptoProviderRequest;
import com.company.incert.ocsp.signing.entity.CryptoDeviceEntity;
import com.company.incert.ocsp.signing.entity.CryptoProviderEntity;
import com.company.incert.ocsp.signing.port.ActivatableCryptoProvider;
import com.company.incert.ocsp.signing.port.CryptoDeviceSpec;
import com.company.incert.ocsp.signing.port.CryptoProviderPort;
import com.company.incert.ocsp.signing.port.DeviceActivationState;
import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
import com.company.incert.ocsp.signing.provider.CryptoDeviceAdapterFactory;
import com.company.incert.ocsp.signing.provider.LibraryPathAllowlist;
import com.company.incert.ocsp.signing.provider.PkcsProviders;
import com.company.incert.ocsp.signing.repository.CryptoDeviceRepository;
import com.company.incert.ocsp.signing.repository.CryptoProviderRepository;
import com.company.incert.ocsp.signing.repository.SigningCertificateRepository;
import com.company.incert.ocsp.signing.service.CryptoDeviceService;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CryptoDeviceServiceTest {

    @Mock
    private CryptoProviderRepository providerRepository;

    @Mock
    private CryptoDeviceRepository deviceRepository;

    @Mock
    private SigningCertificateRepository signingCertificateRepository;

    private LibraryPathAllowlist allowlist;
    private PkcsProviders pkcsProviders;
    private CryptoDeviceService service;

    @BeforeEach
    void setUp() {
        allowlist = new LibraryPathAllowlist(List.of("/usr/lib/softhsm", "/opt/pkcs11j"));
        pkcsProviders = new PkcsProviders();
        CryptoDeviceAdapterFactory fakeFactory = new CryptoDeviceAdapterFactory() {
            @Override
            public boolean supports(String wrapperType) {
                return "PKCS11J".equalsIgnoreCase(wrapperType);
            }

            @Override
            public CryptoProviderPort create(CryptoDeviceSpec spec) {
                return new FakeActivatablePort(spec);
            }
        };
        service = new CryptoDeviceService(
                providerRepository,
                deviceRepository,
                signingCertificateRepository,
                List.of(fakeFactory),
                allowlist,
                pkcsProviders
        );
    }

    @Test
    void createProviderValidatesAllowlistAndPersistsDriverAndWrapper() {
        when(providerRepository.existsByCode("luna")).thenReturn(false);
        when(providerRepository.save(any(CryptoProviderEntity.class))).thenAnswer(inv -> {
            CryptoProviderEntity e = inv.getArgument(0);
            e.setId(5L);
            return e;
        });

        CryptoProviderDto dto = service.createProvider(new CryptoProviderRequest(
                "luna", "SafeNet Luna", "PKCS11J",
                "/usr/lib/softhsm/libsofthsm2.so", "/opt/pkcs11j/libpkcs11j.so", true));

        assertThat(dto.id()).isEqualTo(5L);
        assertThat(dto.libraryWrapperPath()).isEqualTo("/opt/pkcs11j/libpkcs11j.so");

        when(providerRepository.existsByCode("evil")).thenReturn(false);
        assertThatThrownBy(() -> service.createProvider(new CryptoProviderRequest(
                "evil", "Untrusted", "PKCS11J", "/tmp/evil.so", "embedded", true)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside hsm.allowed-library-dirs");
    }

    @Test
    void createAndActivateDeactivateDeviceFollowsPattern2AndWipesPin() {
        CryptoProviderEntity provider = CryptoProviderEntity.builder()
                .id(1L).code("softhsm2").name("SoftHSM v2").wrapperType("PKCS11J")
                .libraryPath("/usr/lib/softhsm/libsofthsm2.so").libraryWrapperPath("embedded").enabled(true).build();

        when(deviceRepository.existsByDeviceId("hsm-a")).thenReturn(false);
        when(providerRepository.findById(1L)).thenReturn(Optional.of(provider));
        when(deviceRepository.findAll()).thenReturn(List.of());
        when(deviceRepository.save(any(CryptoDeviceEntity.class))).thenAnswer(inv -> {
            CryptoDeviceEntity e = inv.getArgument(0);
            e.setId(10L);
            return e;
        });

        CryptoDeviceDto created = service.createDevice(new CryptoDeviceRequest(
                "hsm-a", 1L, "ocsp-signing", null, 0, 4, false, true, true));

        assertThat(created.activationState()).isEqualTo("LOCKED");
        assertThat(created.healthy()).isFalse();

        CryptoDeviceEntity savedEntity = CryptoDeviceEntity.builder()
                .id(10L).deviceId("hsm-a").provider(provider).tokenLabel("ocsp-signing")
                .slotListIndex(0).poolSize(4).defaultDevice(true).enabled(true).build();
        when(deviceRepository.findByDeviceId("hsm-a")).thenReturn(Optional.of(savedEntity));

        char[] pin = "1234".toCharArray();
        CryptoDeviceDto unlocked = service.activateDevice("hsm-a", pin);
        assertThat(pin).containsOnly('\0');
        assertThat(unlocked.activationState()).isEqualTo("ACTIVE");
        assertThat(unlocked.healthy()).isTrue();
        assertThat(unlocked.keyLabels()).containsExactly("ocsp-signing-key");

        CryptoDeviceDto locked = service.deactivateDevice("hsm-a");
        assertThat(locked.activationState()).isEqualTo("LOCKED");
        assertThat(locked.healthy()).isFalse();
    }

    @Test
    void deleteDeviceBlockedWhenActiveSigningCertReferencesIt() {
        CryptoProviderEntity provider = CryptoProviderEntity.builder()
                .id(1L).code("softhsm2").name("SoftHSM").wrapperType("PKCS11J")
                .libraryPath("/usr/lib/softhsm/libsofthsm2.so").libraryWrapperPath("embedded").enabled(true).build();
        CryptoDeviceEntity device = CryptoDeviceEntity.builder()
                .id(9L).deviceId("hsm-in-use").provider(provider).enabled(true).build();

        when(deviceRepository.findById(9L)).thenReturn(Optional.of(device));
        when(signingCertificateRepository.existsByProviderIdAndActiveTrue("hsm-in-use")).thenReturn(true);

        assertThatThrownBy(() -> service.deleteDevice(9L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("active signing certificate references it");
        verify(deviceRepository, never()).delete(any());
    }

    private static final class FakeActivatablePort implements CryptoProviderPort, ActivatableCryptoProvider {
        private final CryptoDeviceSpec spec;
        private DeviceActivationState state = DeviceActivationState.LOCKED;

        FakeActivatablePort(CryptoDeviceSpec spec) {
            this.spec = spec;
        }

        @Override public String providerId() { return spec.deviceId(); }
        @Override public String providerType() { return "PKCS11J"; }
        @Override public DeviceActivationState activationState() { return state; }

        @Override
        public void activate(char[] pin) {
            try {
                this.state = DeviceActivationState.ACTIVE;
            } finally {
                if (pin != null) Arrays.fill(pin, '\0');
            }
        }

        @Override
        public void deactivate() {
            this.state = DeviceActivationState.LOCKED;
        }

        @Override
        public ProviderDeviceInfo getDeviceInfo() {
            boolean up = state == DeviceActivationState.ACTIVE;
            return new ProviderDeviceInfo(
                    spec.deviceId(), "PKCS11J", spec.libraryPath(), spec.libraryWrapperPath(),
                    spec.tokenLabel(), 1L, state.name(), up, up ? "ACTIVE" : "LOCKED",
                    up ? List.of("ocsp-signing-key") : List.of(),
                    up ? Map.of("ocsp-signing-key", "RSA") : Map.of());
        }

        @Override public List<String> listKeyLabels() { return List.of(); }
        @Override public Map<String, String> getKeyAlgorithms() { return Map.of(); }
        @Override public String generateCsr(String l, String dn, String alg, int sz, boolean r) { return ""; }
        @Override public void importCertificate(String l, X509CertificateHolder c) {}
        @Override public byte[] sign(String l, String alg, byte[] d) { return new byte[0]; }
    }
}

