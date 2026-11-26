package lu.incert.ocsp.signing;

import lu.incert.ocsp.signing.pkcs11.*;
import lu.incert.ocsp.signing.port.ProviderCapabilities;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AlgorithmCapabilityValidationTest {

    @Test
    void introspectsSlotMechanismsAndRejectsUnsupportedAlgorithmsBeforeKeyGenOrSign() {
        AtomicInteger keyGenCalls = new AtomicInteger();
        AtomicInteger signInitCalls = new AtomicInteger();

        // Simulate a restricted HSM (e.g. older firmware) supporting ONLY RSA 2048/3072 + SHA256withRSA
        // (NO RSA-PSS, NO SHA-512, NO RSA-4096, NO ECDSA)
        RestrictedFakePkcs11Library fake = new RestrictedFakePkcs11Library(
                Map.of(
                        Pkcs11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN,
                        new MechanismInfo(Pkcs11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN, 2048, 3072,
                                Pkcs11Constants.CKF_GENERATE_KEY_PAIR | Pkcs11Constants.CKF_HW),
                        Pkcs11Constants.CKM_SHA256_RSA_PKCS,
                        new MechanismInfo(Pkcs11Constants.CKM_SHA256_RSA_PKCS, 2048, 3072,
                                Pkcs11Constants.CKF_SIGN | Pkcs11Constants.CKF_HW)
                ),
                Map.of("rsa-key", Pkcs11Constants.CKK_RSA, "ec-key", Pkcs11Constants.CKK_EC),
                keyGenCalls,
                signInitCalls
        );

        try (Pkcs11Engine engine = new Pkcs11Engine((lib, wrapper) -> fake)) {
            Pkcs11Provider provider = engine.register(new Pkcs11ProviderConfig(
                    "utimaco-restricted", "/opt/utimaco/lib/libcs_pkcs11_R3.so", null,
                    "token-1", null, 0, "1234".toCharArray(), 1, false));

            // 1. Live capability introspection reflects actual HSM mechanisms & key-size bounds
            ProviderCapabilities caps = provider.getCapabilities();
            assertThat(caps.liveIntrospected()).isTrue();
            assertThat(caps.supportedSignatureAlgorithms().get("RSA")).containsExactly("SHA256withRSA");
            assertThat(caps.supportedSignatureAlgorithms()).doesNotContainKey("EC");

            ProviderCapabilities.KeyAlgorithmCapability rsaCap = caps.keyAlgorithms().stream()
                    .filter(k -> "RSA".equals(k.keyAlgorithm())).findFirst().orElseThrow();
            assertThat(rsaCap.supported()).isTrue();
            assertThat(rsaCap.supportedKeySizes()).containsExactly(2048, 3072);

            ProviderCapabilities.KeyAlgorithmCapability ecCap = caps.keyAlgorithms().stream()
                    .filter(k -> "EC".equals(k.keyAlgorithm())).findFirst().orElseThrow();
            assertThat(ecCap.supported()).isFalse();
            assertThat(ecCap.reason()).contains("CKM_EC_KEY_PAIR_GEN");

            // 2. Pre-check endpoint logic accepts supported combo and rejects unsupported combos with exact reasons
            ProviderCapabilities.AlgorithmValidationResult ok =
                    provider.checkAlgorithmSupport(null, "RSA", 3072, "SHA256withRSA");
            assertThat(ok.supported()).isTrue();
            assertThat(ok.requiredMechanism()).isEqualTo("CKM_SHA256_RSA_PKCS");

            ProviderCapabilities.AlgorithmValidationResult badPss =
                    provider.checkAlgorithmSupport(null, "RSA", 2048, "SHA256withRSAandMGF1");
            assertThat(badPss.supported()).isFalse();
            assertThat(badPss.message()).contains("CKM_SHA256_RSA_PKCS_PSS");

            ProviderCapabilities.AlgorithmValidationResult badSize =
                    provider.checkAlgorithmSupport(null, "RSA", 4096, "SHA256withRSA");
            assertThat(badSize.supported()).isFalse();
            assertThat(badSize.message()).contains("4096");

            ProviderCapabilities.AlgorithmValidationResult badEc =
                    provider.checkAlgorithmSupport(null, "EC", 256, "SHA256withECDSA");
            assertThat(badEc.supported()).isFalse();
            assertThat(badEc.message()).contains("CKM_EC_KEY_PAIR_GEN");

            ProviderCapabilities.AlgorithmValidationResult keyMismatch =
                    provider.checkAlgorithmSupport("ec-key", null, null, "SHA256withRSA");
            assertThat(keyMismatch.supported()).isFalse();
            assertThat(keyMismatch.message()).contains("requires a RSA key");

            // 3. Pre-signing guards block BEFORE touching C_SignInit
            assertThatThrownBy(() -> provider.sign("rsa-key", "SHA256withRSAandMGF1", "data".getBytes(StandardCharsets.UTF_8)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("CKM_SHA256_RSA_PKCS_PSS");
            assertThatThrownBy(() -> provider.sign("rsa-key", "", "data".getBytes(StandardCharsets.UTF_8)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("signatureAlgorithm must not be blank");
            assertThatThrownBy(() -> provider.sign("ec-key", "SHA256withRSA", "data".getBytes(StandardCharsets.UTF_8)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("has key type EC");
            assertThat(signInitCalls.get()).isZero();

            // 4. Supported signing succeeds
            byte[] sig = provider.sign("rsa-key", "SHA256withRSA", "data".getBytes(StandardCharsets.UTF_8));
            assertThat(sig).isNotEmpty();
            assertThat(signInitCalls.get()).isEqualTo(1);

            // 5. CSR with unsupported signature algorithm fails BEFORE C_GenerateKeyPair (no orphan key!)
            assertThatThrownBy(() -> provider.generateCsr("new-key", "CN=Test", "RSA", 2048, "SHA256withRSAandMGF1", false))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("CKM_SHA256_RSA_PKCS_PSS");
            assertThatThrownBy(() -> provider.generateKeyPair("big-key", "RSA", 4096))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("4096");
            assertThat(keyGenCalls.get()).isZero();
        }
    }

    private static final class RestrictedFakePkcs11Library implements Pkcs11LibraryPort {
        private final Map<Long, MechanismInfo> mechanisms;
        private final Map<String, Long> keyTypesByLabel;
        private final AtomicInteger keyGenCalls;
        private final AtomicInteger signInitCalls;
        private String lastFindLabel;

        RestrictedFakePkcs11Library(
                Map<Long, MechanismInfo> mechanisms,
                Map<String, Long> keyTypesByLabel,
                AtomicInteger keyGenCalls,
                AtomicInteger signInitCalls) {
            this.mechanisms = mechanisms;
            this.keyTypesByLabel = keyTypesByLabel;
            this.keyGenCalls = keyGenCalls;
            this.signInitCalls = signInitCalls;
        }

        @Override public String getLibraryPath() { return "/opt/utimaco/lib/libcs_pkcs11_R3.so"; }
        @Override public long cInitialize(long flags) { return Pkcs11Constants.CKR_OK; }
        @Override public long cFinalize() { return Pkcs11Constants.CKR_OK; }
        @Override public long[] cGetSlotList(boolean tokenPresent) { return new long[]{10L}; }
        @Override public TokenInfo cGetTokenInfo(long slotId) {
            return new TokenInfo(slotId, "token-1", "Utimaco", "CryptoServer", "SN01", Pkcs11Constants.CKF_TOKEN_INITIALIZED);
        }
        @Override public long[] cGetMechanismList(long slotId) {
            return mechanisms.keySet().stream().mapToLong(Long::longValue).toArray();
        }
        @Override public MechanismInfo cGetMechanismInfo(long slotId, long mechanismType) {
            return mechanisms.get(mechanismType);
        }
        @Override public long cOpenSession(long slotId, long flags) { return 100L; }
        @Override public void cCloseSession(long sessionHandle) {}
        @Override public void cCloseAllSessions(long slotId) {}
        @Override public long cLogin(long sessionHandle, long userType, char[] pin) { return Pkcs11Constants.CKR_OK; }
        @Override public long cLogout(long sessionHandle) { return Pkcs11Constants.CKR_OK; }

        @Override
        public void cFindObjectsInit(long sessionHandle, List<Pkcs11Attribute> template) {
            lastFindLabel = null;
            for (Pkcs11Attribute attr : template) {
                if (attr.type() == Pkcs11Constants.CKA_LABEL && attr.byteValue() != null) {
                    lastFindLabel = new String(attr.byteValue(), StandardCharsets.UTF_8);
                }
            }
        }

        @Override
        public long[] cFindObjects(long sessionHandle, int maxCount) {
            if (lastFindLabel != null) {
                return keyTypesByLabel.containsKey(lastFindLabel)
                        ? new long[]{Math.abs(lastFindLabel.hashCode()) + 1L}
                        : new long[0];
            }
            return keyTypesByLabel.keySet().stream().mapToLong(k -> Math.abs(k.hashCode()) + 1L).toArray();
        }

        @Override public void cFindObjectsFinal(long sessionHandle) {}

        @Override
        public byte[] cGetAttributeValue(long sessionHandle, long objectHandle, long attrType) {
            if (attrType == Pkcs11Constants.CKA_LABEL) {
                for (String k : keyTypesByLabel.keySet()) {
                    if (Math.abs(k.hashCode()) + 1L == objectHandle) {
                        return k.getBytes(StandardCharsets.UTF_8);
                    }
                }
            }
            return null;
        }

        @Override
        public long cGetAttributeUlong(long sessionHandle, long objectHandle, long attrType) {
            if (attrType == Pkcs11Constants.CKA_KEY_TYPE) {
                for (var entry : keyTypesByLabel.entrySet()) {
                    if (Math.abs(entry.getKey().hashCode()) + 1L == objectHandle) {
                        return entry.getValue();
                    }
                }
            }
            return Pkcs11Constants.CKK_RSA;
        }

        @Override
        public long[] cGenerateKeyPair(long sessionHandle, Pkcs11Mechanism mechanism,
                                       List<Pkcs11Attribute> pub, List<Pkcs11Attribute> priv) {
            keyGenCalls.incrementAndGet();
            return new long[]{1L, 2L};
        }

        @Override public long cCreateObject(long sessionHandle, List<Pkcs11Attribute> template) { return 55L; }

        @Override
        public void cSignInit(long sessionHandle, Pkcs11Mechanism mechanism, long keyHandle) {
            signInitCalls.incrementAndGet();
        }

        @Override public byte[] cSign(long sessionHandle, byte[] data) { return new byte[]{1, 2, 3, 4}; }
        @Override public void close() {}
    }
}
