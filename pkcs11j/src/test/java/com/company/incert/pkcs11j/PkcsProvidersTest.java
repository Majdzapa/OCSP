package com.company.incert.pkcs11j;

import com.company.incert.pkcs11j.crypto.EcdsaSignatureStrategy;
import com.company.incert.pkcs11j.port.Pkcs11LibraryPort;
import com.company.incert.pkcs11j.provider.Pkcs11Provider;
import com.company.incert.pkcs11j.provider.Pkcs11ProviderConfig;
import com.company.incert.pkcs11j.provider.PkcsProviders;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PkcsProvidersTest {

    @Test
    void multipleProvidersSharingLibraryInitializeOnceAndFinalizeOnLastClose() {
        AtomicInteger initCalls = new AtomicInteger();
        AtomicInteger finalizeCalls = new AtomicInteger();
        AtomicInteger closeCalls = new AtomicInteger();

        PkcsProviders providers = new PkcsProviders(path ->
                new FakePkcs11Library(path, Pkcs11Constants.CKR_OK, initCalls, finalizeCalls, closeCalls));

        providers.register(new Pkcs11ProviderConfig(
                "device-a", "/tmp/libfake.so", "token-a", null, 0, "1234".toCharArray(), 2, false));
        providers.register(new Pkcs11ProviderConfig(
                "device-b", "/tmp/libfake.so", "token-b", null, 0, "1234".toCharArray(), 2, false));

        assertThat(initCalls.get()).isEqualTo(1);
        assertThat(providers.loadedModuleCount()).isEqualTo(1);
        assertThat(providers.listProviderIds()).containsExactly("device-a", "device-b");
        assertThat(providers.getDefaultProviderId()).isEqualTo("device-a");

        providers.getProvider("device-a").close();
        assertThat(finalizeCalls.get()).isZero();
        assertThat(closeCalls.get()).isZero();

        providers.getProvider("device-b").close();
        assertThat(finalizeCalls.get()).isEqualTo(1);
        assertThat(closeCalls.get()).isEqualTo(1);
        assertThat(providers.loadedModuleCount()).isZero();
    }

    @Test
    void cInitializeAlreadyInitializedIsNonFatal() {
        AtomicInteger initCalls = new AtomicInteger();
        AtomicInteger finalizeCalls = new AtomicInteger();
        AtomicInteger closeCalls = new AtomicInteger();

        PkcsProviders providers = new PkcsProviders(path ->
                new FakePkcs11Library(path, Pkcs11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED, initCalls, finalizeCalls, closeCalls));

        Pkcs11Provider provider = providers.register(new Pkcs11ProviderConfig(
                "device-a", "/tmp/libalready.so", "token-a", null, 0, "1234".toCharArray(), 1, false));
        assertThat(provider.getSlotId()).isEqualTo(10L);
        assertThat(initCalls.get()).isEqualTo(1);
        providers.close();
        assertThat(finalizeCalls.get()).isEqualTo(1);
    }

    @Test
    void failedSecondRegistrationDoesNotFinalizeActiveFirstProvider() {
        AtomicInteger initCalls = new AtomicInteger();
        AtomicInteger finalizeCalls = new AtomicInteger();
        AtomicInteger closeCalls = new AtomicInteger();

        PkcsProviders providers = new PkcsProviders(path ->
                new FakePkcs11Library(path, Pkcs11Constants.CKR_OK, initCalls, finalizeCalls, closeCalls));

        providers.register(new Pkcs11ProviderConfig(
                "device-a", "/tmp/libfake.so", "token-a", null, 0, "1234".toCharArray(), 1, false));

        assertThatThrownBy(() -> providers.register(new Pkcs11ProviderConfig(
                "missing-token", "/tmp/libfake.so", "does-not-exist", null, 0, "1234".toCharArray(), 1, false)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("does-not-exist");

        assertThat(finalizeCalls.get()).isZero();
        assertThat(closeCalls.get()).isZero();
        assertThat(providers.loadedModuleCount()).isEqualTo(1);

        providers.close();
        assertThat(finalizeCalls.get()).isEqualTo(1);
    }

    @Test
    void signRetriesOnceWhenSessionHandleInvalid() {
        AtomicInteger initCalls = new AtomicInteger();
        AtomicInteger finalizeCalls = new AtomicInteger();
        AtomicInteger closeCalls = new AtomicInteger();
        FakePkcs11Library fake = new FakePkcs11Library(
                "/tmp/libretry.so", Pkcs11Constants.CKR_OK, initCalls, finalizeCalls, closeCalls);
        fake.failNextSignWithInvalidSession = true;

        try (PkcsProviders providers = new PkcsProviders(path -> fake)) {
            Pkcs11Provider provider = providers.register(new Pkcs11ProviderConfig(
                    "retry-dev", "/tmp/libretry.so", "token-a", null, 0, "1234".toCharArray(), 1, false));
            byte[] sig = provider.sign("key-a", "SHA256withRSA", "hello".getBytes(StandardCharsets.UTF_8));
            assertThat(sig).isEqualTo(new byte[]{1, 2, 3, 4});
            assertThat(fake.signCalls.get()).isEqualTo(2);
        }
    }

    @Test
    void rawEcdsaToDerProducesValidAsn1Sequence() throws Exception {
        byte[] raw = new byte[64];
        raw[0] = (byte) 0x80; // negative if signed, must stay positive ASN1Integer
        raw[31] = 0x11;
        raw[32] = (byte) 0xFF;
        raw[63] = 0x22;

        byte[] der = EcdsaSignatureStrategy.rawEcdsaToDer(raw);
        ASN1Sequence seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der));
        assertThat(seq.size()).isEqualTo(2);
        assertThat(ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue())
                .isEqualTo(new BigInteger(1, java.util.Arrays.copyOfRange(raw, 0, 32)));
        assertThat(ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue())
                .isEqualTo(new BigInteger(1, java.util.Arrays.copyOfRange(raw, 32, 64)));
    }

    @Test
    void openClosedSignatureStrategyExtensionWorksWithoutModifyingProvider() {
        AtomicInteger initCalls = new AtomicInteger();
        AtomicInteger finalizeCalls = new AtomicInteger();
        AtomicInteger closeCalls = new AtomicInteger();
        FakePkcs11Library fake = new FakePkcs11Library(
                "/tmp/libocp.so", Pkcs11Constants.CKR_OK, initCalls, finalizeCalls, closeCalls);

        try (PkcsProviders providers = new PkcsProviders(path -> fake)) {
            providers.getSignatureStrategies().register(new com.company.incert.pkcs11j.crypto.SignatureStrategy() {
                @Override
                public boolean supports(String alg) {
                    return "Ed25519".equalsIgnoreCase(alg);
                }

                @Override
                public byte[] sign(Pkcs11LibraryPort lib, long session, long keyHandle,
                                   String signatureAlgorithm, byte[] data, boolean prehashInJvm) {
                    return new byte[]{9, 9, 9};
                }
            });

            Pkcs11Provider provider = providers.register(new Pkcs11ProviderConfig(
                    "ocp-dev", "/tmp/libocp.so", "token-a", null, 0, "1234".toCharArray(), 1, false));
            byte[] sig = provider.sign("key-a", "Ed25519", "msg".getBytes(StandardCharsets.UTF_8));
            assertThat(sig).isEqualTo(new byte[]{9, 9, 9});
        }
    }

    private static final class FakePkcs11Library implements Pkcs11LibraryPort {
        private final String libraryPath;
        private final long initReturnCode;
        private final AtomicInteger initCalls;
        private final AtomicInteger finalizeCalls;
        private final AtomicInteger closeCalls;
        private final AtomicLong sessionSeq = new AtomicLong(100);
        private final Map<Long, Long> sessionToSlot = new ConcurrentHashMap<>();
        final AtomicInteger signCalls = new AtomicInteger();
        volatile boolean failNextSignWithInvalidSession;

        FakePkcs11Library(
                String libraryPath,
                long initReturnCode,
                AtomicInteger initCalls,
                AtomicInteger finalizeCalls,
                AtomicInteger closeCalls) {
            this.libraryPath = libraryPath;
            this.initReturnCode = initReturnCode;
            this.initCalls = initCalls;
            this.finalizeCalls = finalizeCalls;
            this.closeCalls = closeCalls;
        }

        @Override
        public String getLibraryPath() {
            return libraryPath;
        }

        @Override
        public long cInitialize(long flags) {
            initCalls.incrementAndGet();
            return initReturnCode;
        }

        @Override
        public long cFinalize() {
            finalizeCalls.incrementAndGet();
            return Pkcs11Constants.CKR_OK;
        }

        @Override
        public long[] cGetSlotList(boolean tokenPresent) {
            return new long[]{10L, 20L};
        }

        @Override
        public TokenInfo cGetTokenInfo(long slotId) {
            if (slotId == 10L) {
                return new TokenInfo(10L, "token-a", "Incert", "Soft", "001", Pkcs11Constants.CKF_TOKEN_INITIALIZED);
            }
            return new TokenInfo(20L, "token-b", "Incert", "Soft", "002", Pkcs11Constants.CKF_TOKEN_INITIALIZED);
        }

        @Override
        public long cOpenSession(long slotId, long flags) {
            long h = sessionSeq.incrementAndGet();
            sessionToSlot.put(h, slotId);
            return h;
        }

        @Override
        public void cCloseSession(long sessionHandle) {
            sessionToSlot.remove(sessionHandle);
        }

        @Override
        public void cCloseAllSessions(long slotId) {
            sessionToSlot.entrySet().removeIf(e -> e.getValue().equals(slotId));
        }

        @Override
        public long cLogin(long sessionHandle, long userType, char[] pin) {
            return Pkcs11Constants.CKR_OK;
        }

        @Override
        public long cLogout(long sessionHandle) {
            return Pkcs11Constants.CKR_OK;
        }

        @Override
        public void cFindObjectsInit(long sessionHandle, List<Pkcs11Attribute> template) {}

        @Override
        public long[] cFindObjects(long sessionHandle, int maxCount) {
            return new long[]{999L};
        }

        @Override
        public void cFindObjectsFinal(long sessionHandle) {}

        @Override
        public byte[] cGetAttributeValue(long sessionHandle, long objectHandle, long attrType) {
            return "key-a".getBytes(StandardCharsets.UTF_8);
        }

        @Override
        public long cGetAttributeUlong(long sessionHandle, long objectHandle, long attrType) {
            return Pkcs11Constants.CKK_RSA;
        }

        @Override
        public long[] cGenerateKeyPair(long sessionHandle, Pkcs11Mechanism mechanism,
                                       List<Pkcs11Attribute> pub, List<Pkcs11Attribute> priv) {
            return new long[]{1L, 2L};
        }

        @Override
        public long cCreateObject(long sessionHandle, List<Pkcs11Attribute> template) {
            return 55L;
        }

        @Override
        public void cSignInit(long sessionHandle, Pkcs11Mechanism mechanism, long keyHandle) {}

        @Override
        public byte[] cSign(long sessionHandle, byte[] data) {
            signCalls.incrementAndGet();
            if (failNextSignWithInvalidSession) {
                failNextSignWithInvalidSession = false;
                throw new Pkcs11Exception("C_Sign", Pkcs11Constants.CKR_SESSION_HANDLE_INVALID);
            }
            return new byte[]{1, 2, 3, 4};
        }

        @Override
        public void close() {
            closeCalls.incrementAndGet();
        }
    }
}

