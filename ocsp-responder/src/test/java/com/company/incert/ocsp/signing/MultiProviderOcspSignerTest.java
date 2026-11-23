package com.company.incert.ocsp.signing;

import com.company.incert.hsm.grpc.v1.GenerateCsrRpcRequest;
import com.company.incert.hsm.grpc.v1.GenerateCsrRpcResponse;
import com.company.incert.hsm.grpc.v1.HsmSignerServiceGrpc;
import com.company.incert.hsm.grpc.v1.ImportCertificateRpcRequest;
import com.company.incert.hsm.grpc.v1.ImportCertificateRpcResponse;
import com.company.incert.hsm.grpc.v1.KeyDescriptor;
import com.company.incert.hsm.grpc.v1.ListKeysRequest;
import com.company.incert.hsm.grpc.v1.ListKeysResponse;
import com.company.incert.hsm.grpc.v1.ListProvidersRequest;
import com.company.incert.hsm.grpc.v1.ListProvidersResponse;
import com.company.incert.hsm.grpc.v1.ProviderDescriptor;
import com.company.incert.hsm.grpc.v1.SignRpcRequest;
import com.company.incert.hsm.grpc.v1.SignRpcResponse;
import com.company.incert.ocsp.signing.hsm.MultiProviderOcspSigner;
import com.company.incert.ocsp.signing.hsm.OcspSigner;
import com.company.incert.ocsp.signing.port.CryptoProviderPort;
import com.company.incert.ocsp.signing.port.ProviderDeviceInfo;
import com.company.incert.ocsp.signing.provider.GrpcCryptoProviderAdapter;
import com.company.incert.ocsp.signing.provider.GrpcHsmClient;
import com.company.incert.ocsp.signing.provider.PkcsProviders;
import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class MultiProviderOcspSignerTest {

    @BeforeAll
    static void initBc() {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void routesCaSpecificOcspRequestsAcrossMultipleDevices() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        KeyPair ca1Kp = kpg.generateKeyPair();
        KeyPair ca2Kp = kpg.generateKeyPair();
        KeyPair signer1Kp = kpg.generateKeyPair();
        KeyPair signer2Kp = kpg.generateKeyPair();

        X509CertificateHolder ca1 = buildSelfSignedCa("CN=Root CA One,O=Incert,C=CH", ca1Kp);
        X509CertificateHolder ca2 = buildSelfSignedCa("CN=Root CA Two,O=Incert,C=CH", ca2Kp);

        X509CertificateHolder signer1Cert = buildDelegatedSigner(ca1, ca1Kp, "CN=OCSP Signer 1", signer1Kp, 101L);
        X509CertificateHolder signer2Cert = buildDelegatedSigner(ca2, ca2Kp, "CN=OCSP Signer 2", signer2Kp, 202L);

        InMemoryProvider dev1 = new InMemoryProvider("hsm-ca1", "PKCS11J_GRPC", Map.of("key-1", signer1Kp));
        InMemoryProvider dev2 = new InMemoryProvider("hsm-ca2", "PKCS11J_GRPC", Map.of("key-2", signer2Kp));

        try (PkcsProviders providers = new PkcsProviders()) {
            providers.register(dev1);
            providers.register(dev2);

            MultiProviderOcspSigner multiSigner = new MultiProviderOcspSigner(providers, "key-1");
            multiSigner.updateActiveCertificate("hsm-ca1", "key-1", signer1Cert, "SHA256withRSA");
            multiSigner.syncRegisteredSigners(List.of(
                    new OcspSigner.RegisteredSigner("hsm-ca1", "key-1", signer1Cert, true, "SHA256withRSA"),
                    new OcspSigner.RegisteredSigner("hsm-ca2", "key-2", signer2Cert, false, "SHA256withRSA")
            ));

            DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
            CertificateID idForCa1 = new CertificateID(dcp.get(CertificateID.HASH_SHA1), ca1, BigInteger.valueOf(55));
            CertificateID idForCa2 = new CertificateID(dcp.get(CertificateID.HASH_SHA1), ca2, BigInteger.valueOf(66));

            byte[] payload = "ocsp-basic-response-tbs".getBytes(StandardCharsets.UTF_8);

            OcspSigner.SigningSelection sel1 = multiSigner.selectSigner(idForCa1);
            sel1.contentSigner().getOutputStream().write(payload);
            byte[] sig1 = sel1.contentSigner().getSignature();
            assertThat(sel1.chain()[0].getSubject().toString()).isEqualTo("CN=OCSP Signer 1");
            assertThat(verifySignature(signer1Kp, payload, sig1)).isTrue();
            assertThat(dev1.signCount.get()).isEqualTo(1);
            assertThat(dev2.signCount.get()).isZero();

            OcspSigner.SigningSelection sel2 = multiSigner.selectSigner(idForCa2);
            sel2.contentSigner().getOutputStream().write(payload);
            byte[] sig2 = sel2.contentSigner().getSignature();
            assertThat(sel2.chain()[0].getSubject().toString()).isEqualTo("CN=OCSP Signer 2");
            assertThat(verifySignature(signer2Kp, payload, sig2)).isTrue();
            assertThat(dev2.signCount.get()).isEqualTo(1);
        }
    }

    @Test
    void grpcCryptoProviderAdapterExecutesStatelessSigningAndCsrOverGrpc() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        AtomicReference<String> importedProvider = new AtomicReference<>();
        String serverName = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(serverName)
                .directExecutor()
                .addService(new HsmSignerServiceGrpc.HsmSignerServiceImplBase() {
                    @Override
                    public void listProviders(ListProvidersRequest req, StreamObserver<ListProvidersResponse> obs) {
                        obs.onNext(ListProvidersResponse.newBuilder()
                                .setDefaultProviderId("remote-token-b")
                                .addProviders(ProviderDescriptor.newBuilder()
                                        .setProviderId("remote-token-b")
                                        .setProviderType("PKCS11J")
                                        .setTokenLabel("token-b")
                                        .setSlotId(77)
                                        .setHealthy(true)
                                        .setStatusMessage("UP")
                                        .addKeys(KeyDescriptor.newBuilder()
                                                .setKeyLabel("remote-key")
                                                .setKeyAlgorithm("RSA")
                                                .setKeySize(2048)
                                                .build())
                                        .build())
                                .build());
                        obs.onCompleted();
                    }

                    @Override
                    public void listKeys(ListKeysRequest req, StreamObserver<ListKeysResponse> obs) {
                        obs.onNext(ListKeysResponse.newBuilder()
                                .setProviderId(req.getProviderId())
                                .addKeys(KeyDescriptor.newBuilder()
                                        .setKeyLabel("remote-key")
                                        .setKeyAlgorithm("RSA")
                                        .setKeySize(2048)
                                        .build())
                                .build());
                        obs.onCompleted();
                    }

                    @Override
                    public void generateCsr(GenerateCsrRpcRequest req, StreamObserver<GenerateCsrRpcResponse> obs) {
                        obs.onNext(GenerateCsrRpcResponse.newBuilder()
                                .setProviderId(req.getProviderId())
                                .setKeyLabel(req.getKeyLabel())
                                .setSubjectDn(req.getSubjectDn())
                                .setKeyAlgorithm(req.getKeyAlgorithm())
                                .setCsrPem("-----BEGIN CERTIFICATE REQUEST-----\nREMOTE\n-----END CERTIFICATE REQUEST-----\n")
                                .build());
                        obs.onCompleted();
                    }

                    @Override
                    public void importCertificate(
                            ImportCertificateRpcRequest req, StreamObserver<ImportCertificateRpcResponse> obs) {
                        importedProvider.set(req.getProviderId() + ":" + req.getKeyLabel());
                        obs.onNext(ImportCertificateRpcResponse.newBuilder().setImported(true).setMessage("OK").build());
                        obs.onCompleted();
                    }

                    @Override
                    public void sign(SignRpcRequest req, StreamObserver<SignRpcResponse> obs) {
                        try {
                            Signature sig = Signature.getInstance(req.getSignatureAlgorithm());
                            sig.initSign(kp.getPrivate());
                            sig.update(req.getData().toByteArray());
                            obs.onNext(SignRpcResponse.newBuilder()
                                    .setSignature(ByteString.copyFrom(sig.sign()))
                                    .build());
                            obs.onCompleted();
                        } catch (Exception e) {
                            obs.onError(e);
                        }
                    }
                })
                .build()
                .start();

        ManagedChannel channel = InProcessChannelBuilder.forName(serverName).directExecutor().build();
        GrpcHsmClient client = new GrpcHsmClient(channel, 5);
        try (PkcsProviders providers = new PkcsProviders()) {
            providers.trackManagedClient(client);
            ListProvidersResponse discovered = client.listProviders();
            ProviderDescriptor pd = discovered.getProviders(0);
            providers.register(new GrpcCryptoProviderAdapter(pd.getProviderId(), pd.getProviderId(), client, pd));

            MultiProviderOcspSigner signer = new MultiProviderOcspSigner(providers, "remote-key");
            assertThat(signer.listProviders()).hasSize(1);
            assertThat(signer.listKeyLabels("remote-token-b")).containsExactly("remote-key");

            String csr = signer.generateCsr("remote-token-b", "remote-key", "CN=Remote,O=Incert,C=CH", "RSA", 2048, false);
            assertThat(csr).contains("REMOTE");

            X509CertificateHolder cert = buildSelfSignedCa("CN=Remote,O=Incert,C=CH", kp);
            signer.importCertificateToToken("remote-token-b", "remote-key", cert);
            assertThat(importedProvider.get()).isEqualTo("remote-token-b:remote-key");

            signer.updateActiveCertificate("remote-token-b", "remote-key", cert, "SHA256withRSA");
            signer.syncRegisteredSigners(List.of(
                    new OcspSigner.RegisteredSigner("remote-token-b", "remote-key", cert, true, "SHA256withRSA")
            ));

            byte[] tbs = "grpc-ocsp-tbs".getBytes(StandardCharsets.UTF_8);
            ContentSigner cs = signer.selectSigner(null).contentSigner();
            cs.getOutputStream().write(tbs);
            byte[] signature = cs.getSignature();
            assertThat(verifySignature(kp, tbs, signature)).isTrue();
        } finally {
            server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    private static boolean verifySignature(KeyPair kp, byte[] payload, byte[] sigBytes) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(kp.getPublic());
        s.update(payload);
        return s.verify(sigBytes);
    }

    private static X509CertificateHolder buildSelfSignedCa(String dn, KeyPair kp) throws Exception {
        X500Name name = new X500Name(dn);
        Instant now = Instant.now();
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(
                name, BigInteger.ONE, Date.from(now.minus(1, ChronoUnit.DAYS)), Date.from(now.plus(365, ChronoUnit.DAYS)),
                name, SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
        return b.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate()));
    }

    private static X509CertificateHolder buildDelegatedSigner(
            X509CertificateHolder issuer,
            KeyPair issuerKp,
            String subjectDn,
            KeyPair signerKp,
            long serial) throws Exception {
        Instant now = Instant.now();
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(
                issuer.getSubject(),
                BigInteger.valueOf(serial),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(30, ChronoUnit.DAYS)),
                new X500Name(subjectDn),
                SubjectPublicKeyInfo.getInstance(signerKp.getPublic().getEncoded()));

        // Embed issuer key hash as AuthorityKeyIdentifier just like real CAs do for RFC 6960 matching
        byte[] issuerPubSha1 = java.security.MessageDigest.getInstance("SHA-1")
                .digest(issuer.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
        b.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(issuerPubSha1));
        return b.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKp.getPrivate()));
    }

    private static final class InMemoryProvider implements CryptoProviderPort {
        private final String id;
        private final String type;
        private final Map<String, KeyPair> keys;
        final AtomicInteger signCount = new AtomicInteger();

        InMemoryProvider(String id, String type, Map<String, KeyPair> keys) {
            this.id = id;
            this.type = type;
            this.keys = keys;
        }

        @Override
        public String providerId() {
            return id;
        }

        @Override
        public String providerType() {
            return type;
        }

        @Override
        public ProviderDeviceInfo getDeviceInfo() {
            return new ProviderDeviceInfo(id, type, "mem", id, 0L, true, "UP", listKeyLabels(), getKeyAlgorithms());
        }

        @Override
        public List<String> listKeyLabels() {
            return List.copyOf(keys.keySet());
        }

        @Override
        public Map<String, String> getKeyAlgorithms() {
            Map<String, String> out = new java.util.LinkedHashMap<>();
            keys.forEach((k, v) -> out.put(k, v.getPublic().getAlgorithm()));
            return out;
        }

        @Override
        public String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
            return "";
        }

        @Override
        public void importCertificate(String keyLabel, X509CertificateHolder certificate) {}

        @Override
        public byte[] sign(String keyLabel, String signatureAlgorithm, byte[] data) {
            signCount.incrementAndGet();
            KeyPair kp = keys.get(keyLabel);
            try {
                Signature s = Signature.getInstance(signatureAlgorithm);
                s.initSign(kp.getPrivate());
                s.update(data);
                return s.sign();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public ContentSigner createContentSigner(String keyLabel, String signatureAlgorithm) {
            var algFinder = new org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder();
            return new ContentSigner() {
                private final ByteArrayOutputStream out = new ByteArrayOutputStream();

                @Override
                public org.bouncycastle.asn1.x509.AlgorithmIdentifier getAlgorithmIdentifier() {
                    return algFinder.find(signatureAlgorithm);
                }

                @Override
                public OutputStream getOutputStream() {
                    return out;
                }

                @Override
                public byte[] getSignature() {
                    return sign(keyLabel, signatureAlgorithm, out.toByteArray());
                }
            };
        }
    }
}

