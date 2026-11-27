package lu.incert.ocsp.signing;

import lu.incert.ocsp.signing.config.CryptoProviderLoader;
import lu.incert.ocsp.signing.config.HsmProperties;
import lu.incert.ocsp.signing.config.SigningConfig;
import lu.incert.ocsp.signing.hsm.CaSignerMatcher;
import lu.incert.ocsp.signing.hsm.MultiProviderOcspSigner;
import lu.incert.ocsp.signing.hsm.OcspSigner;
import lu.incert.ocsp.signing.hsm.UnauthorizedIssuerException;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Attribute;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Constants;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Engine;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Exception;
import lu.incert.ocsp.signing.pkcs11.Pkcs11LibraryPort;
import lu.incert.ocsp.signing.pkcs11.Pkcs11Mechanism;
import lu.incert.ocsp.signing.pkcs11.TokenInfo;
import lu.incert.ocsp.signing.port.CryptoDeviceSpec;
import lu.incert.ocsp.signing.port.CryptoProviderPort;
import lu.incert.ocsp.signing.port.DeviceActivationState;
import lu.incert.ocsp.signing.port.DeviceLockedException;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import lu.incert.ocsp.signing.provider.LibraryPathAllowlist;
import lu.incert.ocsp.signing.provider.Pkcs11jCryptoProviderAdapter;
import lu.incert.ocsp.signing.provider.PkcsProviders;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

        InMemoryProvider dev1 = new InMemoryProvider("hsm-ca1", "PKCS11J", Map.of("key-1", signer1Kp));
        InMemoryProvider dev2 = new InMemoryProvider("hsm-ca2", "PKCS11J", Map.of("key-2", signer2Kp));

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

            // Unknown / unauthorized Issuing CA must throw UnauthorizedIssuerException without touching HSM
            KeyPair ca3Kp = kpg.generateKeyPair();
            X509CertificateHolder unknownCa = buildSelfSignedCa("CN=Unknown CA Three,O=Other,C=LU", ca3Kp);
            CertificateID idForUnknownCa = new CertificateID(dcp.get(CertificateID.HASH_SHA1), unknownCa, BigInteger.valueOf(77));
            assertThatThrownBy(() -> multiSigner.selectSigner(idForUnknownCa))
                    .isInstanceOf(UnauthorizedIssuerException.class)
                    .hasMessageContaining("RFC 6960");
            assertThat(dev1.signCount.get()).isEqualTo(1);
            assertThat(dev2.signCount.get()).isEqualTo(1);
        }
    }

    @Test
    void pkcs11jAdapterEnforcesPattern2RuntimeActivationLifecycleAndStrictPinWipe() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X509CertificateHolder cert = buildSelfSignedCa("CN=InProcess,O=Incert,C=CH", kp);

        StubPkcs11Port fakePort = new StubPkcs11Port("/opt/pkcs11j/libfake_hsm.so", kp);
        LibraryPathAllowlist allowlist = new LibraryPathAllowlist(List.of("/opt/pkcs11j"));
        CryptoDeviceSpec spec = new CryptoDeviceSpec(
                "inproc-hsm-1",
                "softhsm2",
                "PKCS11J",
                "/opt/pkcs11j/libfake_hsm.so",
                "/opt/pkcs11j/libpkcs11wrapper.so",
                "token-inproc",
                null,
                0,
                2,
                false
        );

        try (Pkcs11Engine engine = new Pkcs11Engine(path -> fakePort);
             PkcsProviders providers = new PkcsProviders()) {

            Pkcs11jCryptoProviderAdapter adapter = new Pkcs11jCryptoProviderAdapter(spec, engine, allowlist);
            providers.register(adapter);

            MultiProviderOcspSigner signer = new MultiProviderOcspSigner(providers, "key-inproc");
            signer.updateActiveCertificate("inproc-hsm-1", "key-inproc", cert, "SHA256withRSA");
            signer.syncRegisteredSigners(List.of(
                    new OcspSigner.RegisteredSigner("inproc-hsm-1", "key-inproc", cert, true, "SHA256withRSA")
            ));

            // 1. Boots in LOCKED state: info works, signing & CSR throw DeviceLockedException
            assertThat(adapter.activationState()).isEqualTo(DeviceActivationState.LOCKED);
            assertThat(signer.listKeyLabels()).isEmpty();
            assertThatThrownBy(() -> signer.selectSigner(null))
                    .isInstanceOf(DeviceLockedException.class)
                    .hasMessageContaining("LOCKED");
            assertThatThrownBy(() -> signer.generateCsr("inproc-hsm-1", "k", "CN=Test", "RSA", 2048, false))
                    .isInstanceOf(DeviceLockedException.class);

            // 2. Runtime Activation unlocks and immediately wipes incoming PIN buffer
            char[] transientPin = "1234".toCharArray();
            providers.activate("inproc-hsm-1", transientPin);
            assertThat(transientPin).containsOnly('\0');
            assertThat(adapter.activationState()).isEqualTo(DeviceActivationState.ACTIVE);
            assertThat(signer.listKeyLabels("inproc-hsm-1")).containsExactly("key-inproc");

            byte[] tbs = "inprocess-ocsp-tbs".getBytes(StandardCharsets.UTF_8);
            ContentSigner cs = signer.selectSigner(null).contentSigner();
            cs.getOutputStream().write(tbs);
            assertThat(verifySignature(kp, tbs, cs.getSignature())).isTrue();

            // 3. Simulated token logout transitions device back to LOCKED (no silent relogin)
            fakePort.simulateNextSignNotLoggedIn.set(true);
            ContentSigner loggedOutCs = signer.selectSigner(null).contentSigner();
            loggedOutCs.getOutputStream().write(tbs);
            assertThatThrownBy(loggedOutCs::getSignature)
                    .isInstanceOf(DeviceLockedException.class);
            assertThat(adapter.activationState()).isEqualTo(DeviceActivationState.LOCKED);

            // 4. Re-unlock then explicit deactivate()
            providers.activate("inproc-hsm-1", "1234".toCharArray());
            assertThat(adapter.activationState()).isEqualTo(DeviceActivationState.ACTIVE);
            providers.deactivate("inproc-hsm-1");
            assertThat(adapter.activationState()).isEqualTo(DeviceActivationState.LOCKED);
            assertThatThrownBy(() -> signer.selectSigner(null))
                    .isInstanceOf(DeviceLockedException.class);
        }
    }

    @Test
    void caSignerMatcherSelectsPreferredNonExpiredCandidateByIssuerAndAki() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKp = kpg.generateKeyPair();
        KeyPair otherCaKp = kpg.generateKeyPair();
        KeyPair signerKp = kpg.generateKeyPair();

        X509CertificateHolder targetCa = buildSelfSignedCa("CN=Shared CA Name,O=Incert,C=CH", caKp);
        X509CertificateHolder sameDnWrongKeyCa = buildSelfSignedCa("CN=Shared CA Name,O=Incert,C=CH", otherCaKp);

        X509CertificateHolder wrongKeySigner = buildDelegatedSigner(sameDnWrongKeyCa, otherCaKp, "CN=Wrong Key", signerKp, 1L);
        X509CertificateHolder nonPreferred = buildDelegatedSigner(targetCa, caKp, "CN=NonPreferred", signerKp, 2L);
        X509CertificateHolder preferred = buildDelegatedSigner(targetCa, caKp, "CN=Preferred", signerKp, 3L);

        DigestCalculatorProvider dcp = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        CertificateID reqId = new CertificateID(dcp.get(CertificateID.HASH_SHA1), targetCa, BigInteger.TEN);

        var candidates = List.of(
                CaSignerMatcher.MatchedSigner.of("wrong-key", wrongKeySigner, "SHA256withRSA", true),
                CaSignerMatcher.MatchedSigner.of("non-preferred", nonPreferred, "SHA256withRSA", false),
                CaSignerMatcher.MatchedSigner.of("preferred", preferred, "SHA256withRSA", true)
        );
        var match = CaSignerMatcher.selectBest(candidates, reqId);
        assertThat(match).isPresent();
        assertThat(match.get().target()).isEqualTo("preferred");

        // Delegated signer WITHOUT id-kp-OCSPSigning EKU must be rejected (RFC 6960 §2.6)
        X509CertificateHolder nonOcspDelegated = buildDelegatedSigner(targetCa, caKp, "CN=TLS Cert", signerKp, 4L, false);
        var noEkuMatch = CaSignerMatcher.selectBest(
                List.of(CaSignerMatcher.MatchedSigner.of("no-eku", nonOcspDelegated, "SHA256withRSA", true)),
                reqId);
        assertThat(noEkuMatch).isEmpty();

        // Also supports direct CA signing (RFC 6960 §4.2.2.2 case 1: CA signs OCSP with its own key)
        var directCaMatch = CaSignerMatcher.selectBest(
                List.of(CaSignerMatcher.MatchedSigner.of("direct-ca", targetCa, "SHA256withRSA", true)),
                reqId);
        assertThat(directCaMatch).isPresent();
        assertThat(directCaMatch.get().target()).isEqualTo("direct-ca");
    }

    @Test
    void signingConfigDispatchesCustomCryptoProviderLoaderViaOcp() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        HsmProperties props = new HsmProperties();
        props.setEnabled(true);
        props.setMode("AWS_KMS");
        props.setKeyLabel("kms-key");

        CryptoProviderLoader awsLoader = new CryptoProviderLoader() {
            @Override
            public boolean supports(String mode) {
                return "AWS_KMS".equalsIgnoreCase(mode);
            }

            @Override
            public void loadInto(PkcsProviders registry, HsmProperties properties) {
                registry.register(new InMemoryProvider("aws-kms-1", "AWS_KMS", Map.of("kms-key", kp)));
            }
        };

        SigningConfig cfg = new SigningConfig(props);
        try (PkcsProviders providers = cfg.pkcsProviders(List.of(awsLoader))) {
            OcspSigner signer = cfg.multiProviderOcspSigner(providers);
            assertThat(providers.listProviderIds()).containsExactly("aws-kms-1");
            assertThat(signer.type()).isEqualTo("AWS_KMS");
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
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return b.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate()));
    }

    private static X509CertificateHolder buildDelegatedSigner(
            X509CertificateHolder issuer,
            KeyPair issuerKp,
            String subjectDn,
            KeyPair signerKp,
            long serial) throws Exception {
        return buildDelegatedSigner(issuer, issuerKp, subjectDn, signerKp, serial, true);
    }

    private static X509CertificateHolder buildDelegatedSigner(
            X509CertificateHolder issuer,
            KeyPair issuerKp,
            String subjectDn,
            KeyPair signerKp,
            long serial,
            boolean includeOcspSigningEku) throws Exception {
        Instant now = Instant.now();
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(
                issuer.getSubject(),
                BigInteger.valueOf(serial),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(30, ChronoUnit.DAYS)),
                new X500Name(subjectDn),
                SubjectPublicKeyInfo.getInstance(signerKp.getPublic().getEncoded()));

        byte[] issuerPubSha1 = java.security.MessageDigest.getInstance("SHA-1")
                .digest(issuer.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
        b.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(issuerPubSha1));
        if (includeOcspSigningEku) {
            b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        }
        return b.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(issuerKp.getPrivate()));
    }

    private static final class StubPkcs11Port implements Pkcs11LibraryPort {
        private final String libPath;
        private final KeyPair keyPair;
        private final AtomicLong sessions = new AtomicLong(10);
        final AtomicBoolean simulateNextSignNotLoggedIn = new AtomicBoolean(false);

        StubPkcs11Port(String libPath, KeyPair keyPair) {
            this.libPath = libPath;
            this.keyPair = keyPair;
        }

        @Override public String getLibraryPath() { return libPath; }
        @Override public long cInitialize(long flags) { return Pkcs11Constants.CKR_OK; }
        @Override public long cFinalize() { return Pkcs11Constants.CKR_OK; }
        @Override public long[] cGetSlotList(boolean tokenPresent) { return new long[]{1L}; }
        @Override public TokenInfo cGetTokenInfo(long slotId) {
            return new TokenInfo(1L, "token-inproc", "Incert", "SoftHSM", "1", Pkcs11Constants.CKF_TOKEN_INITIALIZED);
        }
        @Override public long cOpenSession(long slotId, long flags) { return sessions.incrementAndGet(); }
        @Override public void cCloseSession(long sessionHandle) {}
        @Override public void cCloseAllSessions(long slotId) {}
        @Override public long cLogin(long sessionHandle, long userType, char[] pin) { return Pkcs11Constants.CKR_OK; }
        @Override public long cLogout(long sessionHandle) { return Pkcs11Constants.CKR_OK; }
        @Override public void cFindObjectsInit(long sessionHandle, List<Pkcs11Attribute> template) {}
        @Override public long[] cFindObjects(long sessionHandle, int maxCount) { return new long[]{501L}; }
        @Override public void cFindObjectsFinal(long sessionHandle) {}
        @Override public byte[] cGetAttributeValue(long sessionHandle, long objectHandle, long attrType) {
            if (attrType == Pkcs11Constants.CKA_MODULUS) {
                return ((RSAPublicKey) keyPair.getPublic()).getModulus().toByteArray();
            }
            if (attrType == Pkcs11Constants.CKA_PUBLIC_EXPONENT) {
                return ((RSAPublicKey) keyPair.getPublic()).getPublicExponent().toByteArray();
            }
            return "key-inproc".getBytes(StandardCharsets.UTF_8);
        }
        @Override public long cGetAttributeUlong(long sessionHandle, long objectHandle, long attrType) {
            return Pkcs11Constants.CKK_RSA;
        }
        @Override public long[] cGenerateKeyPair(long sessionHandle, Pkcs11Mechanism mechanism,
                                               List<Pkcs11Attribute> pub, List<Pkcs11Attribute> priv) {
            return new long[]{500L, 501L};
        }
        @Override public long cCreateObject(long sessionHandle, List<Pkcs11Attribute> template) { return 700L; }
        @Override public void cSignInit(long sessionHandle, Pkcs11Mechanism mechanism, long keyHandle) {}
        @Override public byte[] cSign(long sessionHandle, byte[] data) {
            if (simulateNextSignNotLoggedIn.getAndSet(false)) {
                throw new Pkcs11Exception("C_Sign", Pkcs11Constants.CKR_USER_NOT_LOGGED_IN);
            }
            try {
                Signature s = Signature.getInstance("SHA256withRSA");
                s.initSign(keyPair.getPrivate());
                s.update(data);
                return s.sign();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
        @Override public void close() {}
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

        @Override public String providerId() { return id; }
        @Override public String providerType() { return type; }
        @Override public ProviderDeviceInfo getDeviceInfo() {
            return new ProviderDeviceInfo(id, type, "mem", id, 0L, true, "UP", listKeyLabels(), getKeyAlgorithms());
        }
        @Override public List<String> listKeyLabels() { return List.copyOf(keys.keySet()); }
        @Override public Map<String, String> getKeyAlgorithms() {
            Map<String, String> out = new java.util.LinkedHashMap<>();
            keys.forEach((k, v) -> out.put(k, v.getPublic().getAlgorithm()));
            return out;
        }
        @Override public String generateCsr(String keyLabel, String subjectDn, String keyAlgorithm, int keySize, boolean reuseExistingKey) {
            return "";
        }
        @Override public void importCertificate(String keyLabel, X509CertificateHolder certificate) {}
        @Override public byte[] sign(String keyLabel, String signatureAlgorithm, byte[] data) {
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
    }
}
