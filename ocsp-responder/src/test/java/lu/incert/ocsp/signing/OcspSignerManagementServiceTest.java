package lu.incert.ocsp.signing;

import lu.incert.ocsp.signing.dto.AddSigningCertificateRequest;
import lu.incert.ocsp.signing.dto.GenerateCsrRequest;
import lu.incert.ocsp.signing.dto.GenerateCsrResponse;
import lu.incert.ocsp.signing.dto.SignerCertImportRequest;
import lu.incert.ocsp.signing.dto.SignerCsrRequest;
import lu.incert.ocsp.signing.dto.SignerDto;
import lu.incert.ocsp.signing.dto.SignerRequest;
import lu.incert.ocsp.signing.dto.SigningCertificateDto;
import lu.incert.ocsp.signing.entity.CryptoDeviceEntity;
import lu.incert.ocsp.signing.entity.CryptoProviderEntity;
import lu.incert.ocsp.signing.entity.OcspKeyEntity;
import lu.incert.ocsp.signing.entity.OcspSignerEntity;
import lu.incert.ocsp.signing.hsm.OcspSigner;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import lu.incert.ocsp.signing.repository.CryptoDeviceRepository;
import lu.incert.ocsp.signing.repository.OcspKeyRepository;
import lu.incert.ocsp.signing.repository.OcspSignerRepository;
import lu.incert.ocsp.signing.repository.SigningCertificateRepository;
import lu.incert.ocsp.signing.service.OcspSignerManagementService;
import lu.incert.ocsp.signing.service.SigningCertificateService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OcspSignerManagementServiceTest {

    @Mock private OcspSignerRepository signerRepository;
    @Mock private OcspKeyRepository keyRepository;
    @Mock private CryptoDeviceRepository deviceRepository;
    @Mock private SigningCertificateRepository signingCertRepository;
    @Mock private SigningCertificateService signingCertificateService;
    @Mock private OcspSigner ocspSigner;

    private OcspSignerManagementService service;
    private CryptoDeviceEntity tokenPrimary;
    private CryptoDeviceEntity tokenFailover;
    private KeyPair sampleKeyPair;
    private String sampleCsrPem;
    private String sampleCertPem;

    @BeforeEach
    void setUp() throws Exception {
        service = new OcspSignerManagementService(
                signerRepository, keyRepository, deviceRepository,
                signingCertRepository, signingCertificateService, ocspSigner);

        CryptoProviderEntity prov = CryptoProviderEntity.builder()
                .id(1L).code("softhsm2").name("SoftHSM v2").wrapperType("PKCS11J")
                .libraryPath("/usr/lib/softhsm/libsofthsm2.so").enabled(true).build();
        tokenPrimary = CryptoDeviceEntity.builder()
                .id(10L).deviceId("softhsm-primary").provider(prov).tokenLabel("ocsp-signing").slotListIndex(0).enabled(true).build();
        tokenFailover = CryptoDeviceEntity.builder()
                .id(11L).deviceId("softhsm-secondary").provider(prov).tokenLabel("ocsp-signing-2").slotListIndex(1).enabled(true).build();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        sampleKeyPair = kpg.generateKeyPair();

        var csr = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=Incert OCSP Signer,O=Incert,C=LU"), sampleKeyPair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(sampleKeyPair.getPrivate()));
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(csr);
        }
        sampleCsrPem = sw.toString();

        Instant now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=Incert Root CA,O=Incert,C=LU"),
                BigInteger.valueOf(777),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                new X500Name("CN=Incert OCSP Signer,O=Incert,C=LU"),
                sampleKeyPair.getPublic()
        );
        builder.addExtension(
                org.bouncycastle.asn1.x509.Extension.extendedKeyUsage,
                false,
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning)
        );
        var holder = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(sampleKeyPair.getPrivate()));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
        sampleCertPem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----";
    }

    @Test
    void fullSignerLifecyclePersistsKeyEntityBindsTokensAndImportsCertWithZeroTokenCalls() {
        when(deviceRepository.findByDeviceId("softhsm-primary")).thenReturn(Optional.of(tokenPrimary));
        when(deviceRepository.findByDeviceId("softhsm-secondary")).thenReturn(Optional.of(tokenFailover));
        when(ocspSigner.listProviders()).thenReturn(List.of(
                new ProviderDeviceInfo("softhsm-primary", "PKCS11J", "/usr/lib/softhsm/libsofthsm2.so", null,
                        "ocsp-signing", 101L, "LOCKED", false, "LOCKED", List.of(), Map.of()),
                new ProviderDeviceInfo("softhsm-secondary", "PKCS11J", "/usr/lib/softhsm/libsofthsm2.so", null,
                        "ocsp-signing-2", 202L, "ACTIVE", true, "ACTIVE", List.of(), Map.of())
        ));

        AtomicReference<OcspSignerEntity> storedSigner = new AtomicReference<>();
        AtomicReference<OcspKeyEntity> storedKey = new AtomicReference<>();

        when(signerRepository.save(any(OcspSignerEntity.class))).thenAnswer(inv -> {
            OcspSignerEntity e = inv.getArgument(0);
            if (e.getId() == null) e.setId(1L);
            storedSigner.set(e);
            return e;
        });
        when(signerRepository.findById(1L)).thenAnswer(inv -> Optional.ofNullable(storedSigner.get()));

        when(keyRepository.save(any(OcspKeyEntity.class))).thenAnswer(inv -> {
            OcspKeyEntity k = inv.getArgument(0);
            if (k.getId() == null) k.setId(50L);
            storedKey.set(k);
            return k;
        });
        when(keyRepository.findByKeyLabel(anyString())).thenAnswer(inv -> Optional.ofNullable(storedKey.get()));

        // 1. Create Signer with 2 ordered HSM Tokens (PRIMARY + FAILOVER) — 0 HSM token calls
        SignerDto created = service.createSigner(new SignerRequest(
                "lu-root-signer",
                "Luxembourg Root OCSP Signer",
                "CN=Incert OCSP Signer,O=Incert,C=LU",
                "ocsp-key-lu",
                "RSA",
                2048,
                "SHA384withRSA",
                List.of("softhsm-primary", "softhsm-secondary")
        ));

        assertThat(created.id()).isEqualTo(1L);
        assertThat(created.status()).isEqualTo("DRAFT");
        assertThat(created.key()).isNull();
        assertThat(created.tokens()).hasSize(2);
        assertThat(created.tokens().get(0).deviceId()).isEqualTo("softhsm-primary");
        assertThat(created.tokens().get(0).role()).isEqualTo("PRIMARY");
        assertThat(created.tokens().get(1).deviceId()).isEqualTo("softhsm-secondary");
        assertThat(created.tokens().get(1).role()).isEqualTo("FAILOVER");
        verify(ocspSigner, never()).listKeyLabels(anyString());

        // 2. POST /signer/1/csr -> generates key on ACTIVE token, persists OcspKeyEntity in ocsp_keys, stores CSR
        when(signingCertificateService.generateCsr(any(GenerateCsrRequest.class))).thenReturn(
                new GenerateCsrResponse("softhsm-secondary", "ocsp-key-lu",
                        "CN=Incert OCSP Signer,O=Incert,C=LU", "RSA", sampleCsrPem));

        SignerCsrRequest.SignerCsrResponse csrRes = service.generateCsr(1L, null);
        assertThat(csrRes.tokenDeviceId()).isEqualTo("softhsm-secondary");
        assertThat(csrRes.keyId()).isEqualTo(50L);
        assertThat(csrRes.publicKeySha1()).isNotBlank();
        assertThat(storedKey.get()).isNotNull();
        assertThat(storedKey.get().getPublicKeyPem()).contains("BEGIN PUBLIC KEY");

        // GET /signer/1 now includes the linked Key entity from DB with 0 HSM calls
        SignerDto withKey = service.getById(1L);
        assertThat(withKey.keyId()).isEqualTo(50L);
        assertThat(withKey.key()).isNotNull();
        assertThat(withKey.key().publicKeySha1()).isEqualTo(csrRes.publicKeySha1());

        // 3. POST /signer/1/cert -> imports certificate with ZERO ocspSigner.importCertificateToToken calls!
        Instant notBefore = Instant.now().minus(1, ChronoUnit.DAYS);
        Instant notAfter = Instant.now().plus(365, ChronoUnit.DAYS);
        SigningCertificateDto importedDto = SigningCertificateDto.builder()
                .id(99L)
                .alias("lu-root-signer")
                .providerId("softhsm-secondary")
                .keyLabel("ocsp-key-lu")
                .subjectDn("CN=Incert OCSP Signer,O=Incert,C=LU")
                .issuerDn("CN=Incert Root CA,O=Incert,C=LU")
                .serialNumber("309")
                .notBefore(notBefore)
                .notAfter(notAfter)
                .signatureAlgorithm("SHA384withRSA")
                .certificatePem(sampleCertPem)
                .active(false)
                .build();
        when(signingCertificateService.addCertificate(any(AddSigningCertificateRequest.class))).thenReturn(importedDto);
        when(signingCertificateService.activate(99L)).thenReturn(
                SigningCertificateDto.builder()
                        .id(99L).alias("lu-root-signer").providerId("softhsm-secondary")
                        .keyLabel("ocsp-key-lu").active(true).activatedAt(Instant.now()).build());
        when(signerRepository.findAll()).thenReturn(List.of(storedSigner.get()));

        SignerDto afterImport = service.importCertificate(1L, new SignerCertImportRequest(sampleCertPem, "SHA384withRSA", true));
        assertThat(afterImport.active()).isTrue();
        assertThat(afterImport.status()).isEqualTo("ACTIVE");
        assertThat(afterImport.hasCertificate()).isTrue();
        verify(ocspSigner, never()).importCertificateToToken(anyString(), anyString(), any());
    }

    @Test
    void createSignerAutoGeneratesUuidForCodeAndKeyLabelAndSupportsExistingKeyBinding() {
        when(deviceRepository.findByDeviceId("softhsm-primary")).thenReturn(Optional.of(tokenPrimary));
        when(ocspSigner.listProviders()).thenReturn(List.of());
        when(signerRepository.save(any(OcspSignerEntity.class))).thenAnswer(inv -> {
            OcspSignerEntity e = inv.getArgument(0);
            if (e.getId() == null) e.setId(2L);
            return e;
        });

        SignerDto created = service.createSigner(new SignerRequest(
                null,
                "UUID Signer",
                "CN=Incert UUID Signer,O=Incert,C=LU",
                "",
                "RSA",
                3072,
                "SHA256withRSA",
                List.of("softhsm-primary")
        ));

        assertThat(created.code()).matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
        assertThat(created.keyLabel()).matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");

        // Now bind an existing OcspKeyEntity (e.g. renewal signer)
        OcspKeyEntity existingKey = OcspKeyEntity.builder()
                .id(77L)
                .keyLabel("550e8400-e29b-41d4-a716-446655440000")
                .tokenDevice(tokenPrimary)
                .keyAlgorithm("EC")
                .keySize(256)
                .publicKeyPem("-----BEGIN PUBLIC KEY-----\nMFkwEw...\n-----END PUBLIC KEY-----")
                .publicKeySha1("abcd1234")
                .build();
        when(keyRepository.findById(77L)).thenReturn(Optional.of(existingKey));

        SignerDto bound = service.createSigner(new SignerRequest(
                null,
                "Renewal EC Signer",
                "CN=Incert EC Signer,O=Incert,C=LU",
                77L,
                null,
                null,
                null,
                "SHA256withECDSA",
                List.of("softhsm-primary")
        ));

        assertThat(bound.keyId()).isEqualTo(77L);
        assertThat(bound.keyLabel()).isEqualTo("550e8400-e29b-41d4-a716-446655440000");
        assertThat(bound.keyAlgorithm()).isEqualTo("EC");
        assertThat(bound.keySize()).isEqualTo(256);
    }

    @Test
    void regenerateCsrGeneratesBrandNewKeyWithFreshUuidLabel() {
        when(deviceRepository.findByDeviceId("softhsm-primary")).thenReturn(Optional.of(tokenPrimary));
        when(ocspSigner.listProviders()).thenReturn(List.of(
                new ProviderDeviceInfo("softhsm-primary", "PKCS11J", "/usr/lib/softhsm/libsofthsm2.so", null,
                        "ocsp-signing", 101L, "ACTIVE", true, "ACTIVE", List.of(), Map.of())
        ));

        AtomicReference<OcspSignerEntity> storedSigner = new AtomicReference<>();
        java.util.concurrent.atomic.AtomicLong keyIdSeq = new java.util.concurrent.atomic.AtomicLong(100L);

        when(signerRepository.save(any(OcspSignerEntity.class))).thenAnswer(inv -> {
            OcspSignerEntity e = inv.getArgument(0);
            if (e.getId() == null) e.setId(9L);
            storedSigner.set(e);
            return e;
        });
        when(signerRepository.findById(9L)).thenAnswer(inv -> Optional.ofNullable(storedSigner.get()));
        when(keyRepository.save(any(OcspKeyEntity.class))).thenAnswer(inv -> {
            OcspKeyEntity k = inv.getArgument(0);
            if (k.getId() == null) k.setId(keyIdSeq.incrementAndGet());
            return k;
        });
        when(signingCertificateService.generateCsr(any(GenerateCsrRequest.class))).thenAnswer(inv -> {
            GenerateCsrRequest req = inv.getArgument(0);
            assertThat(req.reuseExistingKey()).isFalse();
            return new GenerateCsrResponse("softhsm-primary", req.keyLabel(), req.subjectDn(), "RSA", sampleCsrPem);
        });

        SignerDto created = service.createSigner(new SignerRequest(
                null, "Regen Test Signer", "CN=Incert Regen,O=Incert,C=LU",
                null, "RSA", 2048, "SHA256withRSA", List.of("softhsm-primary")));

        // 1st CSR generation
        var firstCsr = service.generateCsr(9L, null);
        assertThat(firstCsr.keyId()).isEqualTo(101L);
        assertThat(firstCsr.keyLabel()).isEqualTo(created.keyLabel());

        // 2nd CSR generation (re-generate): MUST generate a brand-new UUID keyLabel & new OcspKeyEntity
        var secondCsr = service.generateCsr(9L, null);
        assertThat(secondCsr.keyId()).isEqualTo(102L);
        assertThat(secondCsr.keyLabel()).isNotEqualTo(firstCsr.keyLabel());
        assertThat(secondCsr.keyLabel())
                .matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
        assertThat(storedSigner.get().getKeyLabel()).isEqualTo(secondCsr.keyLabel());
        assertThat(storedSigner.get().getKey().getId()).isEqualTo(102L);
    }

    @Test
    void updateSignerUpdatesExistingTokenBindingsInPlaceWhenAddingOrReorderingTokens() {
        when(deviceRepository.findByDeviceId("softhsm-primary")).thenReturn(Optional.of(tokenPrimary));
        when(deviceRepository.findByDeviceId("softhsm-secondary")).thenReturn(Optional.of(tokenFailover));
        when(ocspSigner.listProviders()).thenReturn(List.of());

        AtomicReference<OcspSignerEntity> storedSigner = new AtomicReference<>();
        when(signerRepository.save(any(OcspSignerEntity.class))).thenAnswer(inv -> {
            OcspSignerEntity e = inv.getArgument(0);
            if (e.getId() == null) e.setId(1L);
            for (int i = 0; i < e.getTokens().size(); i++) {
                if (e.getTokens().get(i).getId() == null) {
                    e.getTokens().get(i).setId(1000L + i);
                }
            }
            storedSigner.set(e);
            return e;
        });
        when(signerRepository.findById(1L)).thenAnswer(inv -> Optional.ofNullable(storedSigner.get()));

        service.createSigner(new SignerRequest(
                "signer-tokens-update", "Update Tokens Signer", "CN=Test,O=Incert,C=LU",
                "key-update-1", "RSA", 2048, "SHA256withRSA", List.of("softhsm-primary")));
        Long originalPrimaryRowId = storedSigner.get().getTokens().get(0).getId();
        assertThat(originalPrimaryRowId).isEqualTo(1000L);

        // Add second HSM token and swap order so softhsm-secondary becomes PRIMARY and softhsm-primary becomes FAILOVER
        SignerDto updated = service.updateSigner(1L, new SignerRequest(
                "signer-tokens-update", "Update Tokens Signer", "CN=Test,O=Incert,C=LU",
                "key-update-1", "RSA", 2048, "SHA256withRSA", List.of("softhsm-secondary", "softhsm-primary")));

        assertThat(updated.tokens()).hasSize(2);
        assertThat(updated.tokens().get(0).deviceId()).isEqualTo("softhsm-secondary");
        assertThat(updated.tokens().get(0).role()).isEqualTo("PRIMARY");
        assertThat(updated.tokens().get(1).deviceId()).isEqualTo("softhsm-primary");
        assertThat(updated.tokens().get(1).role()).isEqualTo("FAILOVER");
        // Verify existing (signer_id=1, token_device_id=primary) row kept its DB id in-place (no duplicate re-insert)
        assertThat(storedSigner.get().getTokens().get(1).getId()).isEqualTo(originalPrimaryRowId);
    }

    @Test
    void ejbcaRulesEnforceSingleActiveKeyPerTokenAndMarkKeysUnavailableWhenTokenDeactivated() {
        OcspKeyEntity key1 = OcspKeyEntity.builder()
                .id(201L).keyLabel("key-1").tokenDevice(tokenPrimary)
                .keyAlgorithm("RSA").keySize(2048).publicKeyPem("PEM1").publicKeySha1("aaa").build();
        OcspKeyEntity key2 = OcspKeyEntity.builder()
                .id(202L).keyLabel("key-2").tokenDevice(tokenPrimary)
                .keyAlgorithm("RSA").keySize(2048).publicKeyPem("PEM2").publicKeySha1("bbb").build();

        OcspSignerEntity signer1 = OcspSignerEntity.builder()
                .id(1L).code("s1").name("Signer 1").status("ACTIVE").subjectDn("CN=S1")
                .key(key1).keyLabel("key-1").keyAlgorithm("RSA").keySize(2048)
                .signatureAlgorithm("SHA256withRSA").certificatePem(sampleCertPem)
                .certNotAfter(Instant.now().plus(30, ChronoUnit.DAYS))
                .signingCertificateId(51L).active(true).build();
        signer1.getTokens().add(lu.incert.ocsp.signing.entity.OcspSignerTokenEntity.builder()
                .id(1L).signer(signer1).tokenDevice(tokenPrimary).priorityOrder(0).role("PRIMARY").build());

        OcspSignerEntity signer2 = OcspSignerEntity.builder()
                .id(2L).code("s2").name("Signer 2").status("CERT_IMPORTED").subjectDn("CN=S2")
                .key(key2).keyLabel("key-2").keyAlgorithm("RSA").keySize(2048)
                .signatureAlgorithm("SHA256withRSA").certificatePem(sampleCertPem)
                .certNotAfter(Instant.now().plus(30, ChronoUnit.DAYS))
                .signingCertificateId(52L).active(false).build();
        signer2.getTokens().add(lu.incert.ocsp.signing.entity.OcspSignerTokenEntity.builder()
                .id(2L).signer(signer2).tokenDevice(tokenPrimary).priorityOrder(0).role("PRIMARY").build());

        when(keyRepository.findAllByOrderByIdDesc()).thenReturn(List.of(key2, key1));
        when(signerRepository.findAllByOrderByIdAsc()).thenReturn(List.of(signer1, signer2));
        when(signerRepository.findAll()).thenReturn(List.of(signer1, signer2));
        when(signerRepository.findById(2L)).thenReturn(Optional.of(signer2));
        when(signerRepository.save(any(OcspSignerEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        // 1. When token is DEACTIVATED (LOCKED), all keys in that token are UNAVAILABLE and activation is rejected
        when(ocspSigner.listProviders()).thenReturn(List.of(
                new ProviderDeviceInfo("softhsm-primary", "PKCS11J", "/usr/lib/softhsm/libsofthsm2.so", null,
                        "ocsp-signing", 101L, "LOCKED", false, "LOCKED", List.of(), Map.of())
        ));
        var lockedKeys = service.listKeys();
        assertThat(lockedKeys).hasSize(2);
        assertThat(lockedKeys).allSatisfy(k -> {
            assertThat(k.tokenActive()).isFalse();
            assertThat(k.status()).isEqualTo("UNAVAILABLE");
        });
        assertThatThrownBy(() -> service.activateSigner(2L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("deactivated/LOCKED");

        // 2. When token is ACTIVE, activating signer2 auto-deactivates signer1 (max 1 active key per token)
        when(ocspSigner.listProviders()).thenReturn(List.of(
                new ProviderDeviceInfo("softhsm-primary", "PKCS11J", "/usr/lib/softhsm/libsofthsm2.so", null,
                        "ocsp-signing", 101L, "ACTIVE", true, "ACTIVE", List.of(), Map.of())
        ));
        when(signingCertificateService.activate(52L)).thenReturn(SigningCertificateDto.builder()
                .id(52L).alias("s2").active(true).activatedAt(Instant.now()).build());

        SignerDto activated = service.activateSigner(2L);
        assertThat(activated.active()).isTrue();
        assertThat(activated.status()).isEqualTo("ACTIVE");
        assertThat(signer1.isActive()).isFalse();
        assertThat(signer1.getStatus()).isEqualTo("INACTIVE");

        var activeKeys = service.listKeys();
        assertThat(activeKeys.stream().filter(k -> "ACTIVE".equals(k.status())).count()).isEqualTo(1);
        assertThat(activeKeys.stream().filter(k -> "READY".equals(k.status())).count()).isEqualTo(1);
    }

    @Test
    void zeroDowntimeMultiKeyRolloverUnderSingleSignerSwitchesActiveKeyAtomically() {
        OcspKeyEntity key1 = OcspKeyEntity.builder()
                .id(301L).keyLabel("key-active-1").tokenDevice(tokenPrimary)
                .keyAlgorithm("RSA").keySize(2048).publicKeyPem("PEM1").publicKeySha1("111")
                .certificatePem(sampleCertPem).certNotAfter(Instant.now().plus(30, ChronoUnit.DAYS))
                .signingCertificateId(61L).active(true).build();
        OcspKeyEntity key2 = OcspKeyEntity.builder()
                .id(302L).keyLabel("key-next-2").tokenDevice(tokenPrimary)
                .keyAlgorithm("RSA").keySize(2048).publicKeyPem("PEM2").publicKeySha1("222")
                .certificatePem(sampleCertPem).certNotAfter(Instant.now().plus(90, ChronoUnit.DAYS))
                .signingCertificateId(62L).active(false).build();

        OcspSignerEntity signer = OcspSignerEntity.builder()
                .id(7L).code("rollover-signer").name("Rollover Signer").status("ACTIVE").subjectDn("CN=Rollover")
                .key(key1).keyLabel("key-active-1").keyAlgorithm("RSA").keySize(2048)
                .signatureAlgorithm("SHA256withRSA").certificatePem(sampleCertPem)
                .certNotAfter(Instant.now().plus(30, ChronoUnit.DAYS))
                .signingCertificateId(61L).active(true).build();
        signer.getTokens().add(lu.incert.ocsp.signing.entity.OcspSignerTokenEntity.builder()
                .id(70L).signer(signer).tokenDevice(tokenPrimary).priorityOrder(0).role("PRIMARY").build());
        key1.setSigner(signer);
        key2.setSigner(signer);

        when(signerRepository.findById(7L)).thenReturn(Optional.of(signer));
        when(signerRepository.findAll()).thenReturn(List.of(signer));
        when(signerRepository.save(any(OcspSignerEntity.class))).thenAnswer(inv -> inv.getArgument(0));
        when(keyRepository.findById(302L)).thenReturn(Optional.of(key2));
        when(keyRepository.findAllBySigner_IdOrderByIdDesc(7L)).thenReturn(List.of(key2, key1));
        when(keyRepository.save(any(OcspKeyEntity.class))).thenAnswer(inv -> inv.getArgument(0));
        when(ocspSigner.listProviders()).thenReturn(List.of(
                new ProviderDeviceInfo("softhsm-primary", "PKCS11J", "/usr/lib/softhsm/libsofthsm2.so", null,
                        "ocsp-signing", 101L, "ACTIVE", true, "ACTIVE", List.of(), Map.of())
        ));
        when(signingCertificateService.activate(62L)).thenReturn(SigningCertificateDto.builder()
                .id(62L).alias("rollover-signer-k302").signatureAlgorithm("SHA256withRSA")
                .active(true).activatedAt(Instant.now()).build());

        SignerDto switched = service.activateKey(7L, 302L);
        assertThat(switched.keyId()).isEqualTo(302L);
        assertThat(switched.keyLabel()).isEqualTo("key-next-2");
        assertThat(key2.isActive()).isTrue();
        assertThat(key1.isActive()).isFalse();
        assertThat(switched.keys()).hasSize(2);
        assertThat(switched.keys().stream().filter(k -> "ACTIVE".equals(k.status())).count()).isEqualTo(1);
        assertThat(switched.keys().stream().filter(k -> "READY".equals(k.status())).count()).isEqualTo(1);
    }

    @Test
    void attachExistingKeyAndLinkUnlinkTokenWorkOnSigner() {
        OcspSignerEntity signer = OcspSignerEntity.builder()
                .id(12L).code("link-signer").name("Link Signer").status("DRAFT").subjectDn("CN=Link")
                .keyLabel("initial").keyAlgorithm("RSA").keySize(2048)
                .signatureAlgorithm("SHA256withRSA").active(false).build();
        signer.getTokens().add(lu.incert.ocsp.signing.entity.OcspSignerTokenEntity.builder()
                .id(120L).signer(signer).tokenDevice(tokenPrimary).priorityOrder(0).role("PRIMARY").build());

        OcspKeyEntity existingKey = OcspKeyEntity.builder()
                .id(401L).keyLabel("preexisting-key").tokenDevice(tokenFailover)
                .keyAlgorithm("RSA").keySize(2048).publicKeyPem("PEM").publicKeySha1("abc").active(false).build();

        when(signerRepository.findById(12L)).thenReturn(Optional.of(signer));
        when(signerRepository.save(any(OcspSignerEntity.class))).thenAnswer(inv -> inv.getArgument(0));
        when(keyRepository.findById(401L)).thenReturn(Optional.of(existingKey));
        when(keyRepository.save(any(OcspKeyEntity.class))).thenAnswer(inv -> inv.getArgument(0));
        when(keyRepository.findAllBySigner_IdOrderByIdDesc(12L)).thenReturn(List.of(existingKey));
        when(deviceRepository.findByDeviceId("softhsm-secondary")).thenReturn(Optional.of(tokenFailover));
        when(ocspSigner.listProviders()).thenReturn(List.of());

        // Attach existing key on tokenFailover -> automatically links tokenFailover too!
        SignerDto afterAttach = service.attachKeyToSigner(12L, 401L);
        assertThat(existingKey.getSigner()).isSameAs(signer);
        assertThat(afterAttach.tokens()).hasSize(2);
        assertThat(afterAttach.keys()).hasSize(1);
        assertThat(afterAttach.keys().get(0).keyLabel()).isEqualTo("preexisting-key");

        // Unlink tokenFailover
        SignerDto afterUnlink = service.unlinkTokenFromSigner(12L, "softhsm-secondary");
        assertThat(afterUnlink.tokens()).hasSize(1);
        assertThat(afterUnlink.tokens().get(0).deviceId()).isEqualTo("softhsm-primary");

        // Re-link tokenFailover explicitly
        SignerDto afterRelink = service.linkTokenToSigner(12L, "softhsm-secondary");
        assertThat(afterRelink.tokens()).hasSize(2);
        assertThat(afterRelink.tokens().get(1).role()).isEqualTo("FAILOVER");
    }
}
