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
}
