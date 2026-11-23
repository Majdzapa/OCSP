package com.company.incert.hsmsigner;

import com.company.incert.hsm.grpc.v1.GenerateCsrRpcRequest;
import com.company.incert.hsm.grpc.v1.GenerateCsrRpcResponse;
import com.company.incert.hsm.grpc.v1.HealthRpcRequest;
import com.company.incert.hsm.grpc.v1.HealthRpcResponse;
import com.company.incert.hsm.grpc.v1.HsmSignerServiceGrpc;
import com.company.incert.hsm.grpc.v1.ImportCertificateRpcRequest;
import com.company.incert.hsm.grpc.v1.ImportCertificateRpcResponse;
import com.company.incert.hsm.grpc.v1.ListKeysRequest;
import com.company.incert.hsm.grpc.v1.ListKeysResponse;
import com.company.incert.hsm.grpc.v1.ListProvidersRequest;
import com.company.incert.hsm.grpc.v1.ListProvidersResponse;
import com.company.incert.hsm.grpc.v1.SignRpcRequest;
import com.company.incert.hsm.grpc.v1.SignRpcResponse;
import com.company.incert.hsmsigner.grpc.HsmSignerGrpcService;
import com.company.incert.pkcs11j.Pkcs11Attribute;
import com.company.incert.pkcs11j.Pkcs11Constants;
import com.company.incert.pkcs11j.Pkcs11Mechanism;
import com.company.incert.pkcs11j.TokenInfo;
import com.company.incert.pkcs11j.port.Pkcs11LibraryPort;
import com.company.incert.pkcs11j.provider.Pkcs11ProviderConfig;
import com.company.incert.pkcs11j.provider.PkcsProviders;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HsmSignerGrpcServiceTest {

    private PkcsProviders pkcsProviders;
    private Server server;
    private ManagedChannel channel;
    private HsmSignerServiceGrpc.HsmSignerServiceBlockingStub stub;
    private KeyPair rsaKey1;
    private KeyPair rsaKey2;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKey1 = kpg.generateKeyPair();
        rsaKey2 = kpg.generateKeyPair();

        FakeMultiDeviceLibrary fakeLib = new FakeMultiDeviceLibrary(rsaKey1, rsaKey2);
        pkcsProviders = new PkcsProviders(path -> fakeLib);
        pkcsProviders.register(new Pkcs11ProviderConfig(
                "device-1", "/tmp/libdev.so", "token-1", null, 0, "1234".toCharArray(), 2, false));
        pkcsProviders.register(new Pkcs11ProviderConfig(
                "device-2", "/tmp/libdev.so", "token-2", null, 0, "1234".toCharArray(), 2, false));

        String serverName = InProcessServerBuilder.generateName();
        server = InProcessServerBuilder.forName(serverName)
                .directExecutor()
                .addService(new HsmSignerGrpcService(pkcsProviders))
                .build()
                .start();
        channel = InProcessChannelBuilder.forName(serverName)
                .directExecutor()
                .build();
        stub = HsmSignerServiceGrpc.newBlockingStub(channel);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (channel != null) {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
        if (server != null) {
            server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
        if (pkcsProviders != null) {
            pkcsProviders.close();
        }
    }

    @Test
    void listsMultipleProvidersKeysSignsImportsAndChecksHealth() throws Exception {
        ListProvidersResponse providersResp = stub.listProviders(ListProvidersRequest.getDefaultInstance());
        assertThat(providersResp.getDefaultProviderId()).isEqualTo("device-1");
        assertThat(providersResp.getProvidersList()).hasSize(2);
        assertThat(providersResp.getProvidersList())
                .extracting("providerId", "tokenLabel", "healthy")
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple("device-1", "token-1", true),
                        org.assertj.core.groups.Tuple.tuple("device-2", "token-2", true)
                );

        ListKeysResponse keys2 = stub.listKeys(ListKeysRequest.newBuilder().setProviderId("device-2").build());
        assertThat(keys2.getProviderId()).isEqualTo("device-2");
        assertThat(keys2.getKeysList()).extracting("keyLabel").containsExactly("key-two");

        GenerateCsrRpcResponse csrResp = stub.generateCsr(GenerateCsrRpcRequest.newBuilder()
                .setProviderId("device-2")
                .setKeyLabel("key-two")
                .setSubjectDn("CN=Device2 Signer,O=Incert,C=CH")
                .setKeyAlgorithm("RSA")
                .setKeySize(2048)
                .setReuseExistingKey(true)
                .build());
        assertThat(csrResp.getProviderId()).isEqualTo("device-2");
        assertThat(csrResp.getCsrPem()).contains("BEGIN CERTIFICATE REQUEST");

        byte[] payload = "ocsp-tbs-data".getBytes(StandardCharsets.UTF_8);
        SignRpcResponse signResp = stub.sign(SignRpcRequest.newBuilder()
                .setProviderId("device-1")
                .setKeyLabel("key-one")
                .setSignatureAlgorithm("SHA256withRSA")
                .setData(ByteString.copyFrom(payload))
                .build());
        Signature verify1 = Signature.getInstance("SHA256withRSA");
        verify1.initVerify(rsaKey1.getPublic());
        verify1.update(payload);
        assertThat(verify1.verify(signResp.getSignature().toByteArray())).isTrue();

        X509CertificateHolder cert1 = buildCert(rsaKey1);
        ImportCertificateRpcResponse importResp = stub.importCertificate(ImportCertificateRpcRequest.newBuilder()
                .setProviderId("device-1")
                .setKeyLabel("key-one")
                .setCertificateDer(ByteString.copyFrom(cert1.getEncoded()))
                .build());
        assertThat(importResp.getImported()).isTrue();

        HealthRpcResponse healthResp = stub.health(HealthRpcRequest.getDefaultInstance());
        assertThat(healthResp.getHealthy()).isTrue();
        assertThat(healthResp.getProvidersList()).hasSize(2);
    }

    @Test
    void unknownProviderReturnsInvalidArgumentGrpcStatus() {
        assertThatThrownBy(() -> stub.listKeys(ListKeysRequest.newBuilder().setProviderId("no-such-device").build()))
                .isInstanceOf(StatusRuntimeException.class)
                .hasMessageContaining("INVALID_ARGUMENT");
    }

    private static X509CertificateHolder buildCert(KeyPair kp) throws Exception {
        X500Name dn = new X500Name("CN=Device1 Signer,O=Incert,C=CH");
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                dn,
                BigInteger.valueOf(42),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(30, ChronoUnit.DAYS)),
                dn,
                SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return builder.build(cs);
    }

    private static final class FakeMultiDeviceLibrary implements Pkcs11LibraryPort {
        private final KeyPair kp1;
        private final KeyPair kp2;
        private final AtomicLong seq = new AtomicLong(10);
        private final Map<Long, Long> sessionToSlot = new ConcurrentHashMap<>();
        private final Map<Long, Long> activeSlotSignKey = new ConcurrentHashMap<>();
        private volatile Long findSlot;

        FakeMultiDeviceLibrary(KeyPair kp1, KeyPair kp2) {
            this.kp1 = kp1;
            this.kp2 = kp2;
        }

        @Override
        public String getLibraryPath() {
            return "/tmp/libdev.so";
        }

        @Override
        public long cInitialize(long flags) {
            return Pkcs11Constants.CKR_OK;
        }

        @Override
        public long cFinalize() {
            return Pkcs11Constants.CKR_OK;
        }

        @Override
        public long[] cGetSlotList(boolean tokenPresent) {
            return new long[]{1L, 2L};
        }

        @Override
        public TokenInfo cGetTokenInfo(long slotId) {
            return slotId == 1L
                    ? new TokenInfo(1L, "token-1", "Incert", "Sim", "S1", 0L)
                    : new TokenInfo(2L, "token-2", "Incert", "Sim", "S2", 0L);
        }

        @Override
        public long cOpenSession(long slotId, long flags) {
            long s = seq.incrementAndGet();
            sessionToSlot.put(s, slotId);
            return s;
        }

        @Override
        public void cCloseSession(long sessionHandle) {
            sessionToSlot.remove(sessionHandle);
        }

        @Override
        public void cCloseAllSessions(long slotId) {}

        @Override
        public long cLogin(long sessionHandle, long userType, char[] pin) {
            return Pkcs11Constants.CKR_OK;
        }

        @Override
        public long cLogout(long sessionHandle) {
            return Pkcs11Constants.CKR_OK;
        }

        @Override
        public void cFindObjectsInit(long sessionHandle, List<Pkcs11Attribute> template) {
            findSlot = sessionToSlot.get(sessionHandle);
        }

        @Override
        public long[] cFindObjects(long sessionHandle, int maxCount) {
            Long slot = findSlot;
            findSlot = null;
            if (slot == null) {
                return new long[0];
            }
            return new long[]{slot == 1L ? 101L : 201L};
        }

        @Override
        public void cFindObjectsFinal(long sessionHandle) {}

        @Override
        public byte[] cGetAttributeValue(long sessionHandle, long objectHandle, long attrType) {
            KeyPair kp = objectHandle == 101L ? kp1 : kp2;
            String label = objectHandle == 101L ? "key-one" : "key-two";
            if (attrType == Pkcs11Constants.CKA_LABEL) {
                return label.getBytes(StandardCharsets.UTF_8);
            }
            if (attrType == Pkcs11Constants.CKA_MODULUS) {
                return ((RSAPublicKey) kp.getPublic()).getModulus().toByteArray();
            }
            if (attrType == Pkcs11Constants.CKA_PUBLIC_EXPONENT) {
                return ((RSAPublicKey) kp.getPublic()).getPublicExponent().toByteArray();
            }
            return new byte[0];
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
            return 500L;
        }

        @Override
        public void cSignInit(long sessionHandle, Pkcs11Mechanism mechanism, long keyHandle) {
            activeSlotSignKey.put(sessionHandle, keyHandle);
        }

        @Override
        public byte[] cSign(long sessionHandle, byte[] data) {
            long keyHandle = activeSlotSignKey.getOrDefault(sessionHandle, 101L);
            KeyPair kp = keyHandle == 101L ? kp1 : kp2;
            try {
                Signature sig = Signature.getInstance("SHA256withRSA");
                sig.initSign(kp.getPrivate());
                sig.update(data);
                return sig.sign();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public void close() {}
    }
}

