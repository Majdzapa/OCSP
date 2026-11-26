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
import lu.incert.ocsp.signing.entity.OcspSignerEntity;
import lu.incert.ocsp.signing.hsm.OcspSigner;
import lu.incert.ocsp.signing.port.ProviderDeviceInfo;
import lu.incert.ocsp.signing.repository.CryptoDeviceRepository;
import lu.incert.ocsp.signing.repository.OcspSignerRepository;
import lu.incert.ocsp.signing.repository.SigningCertificateRepository;
import lu.incert.ocsp.signing.service.OcspSignerManagementService;
import lu.incert.ocsp.signing.service.SigningCertificateService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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
    @Mock private CryptoDeviceRepository deviceRepository;
    @Mock private SigningCertificateRepository signingCertRepository;
    @Mock private SigningCertificateService signingCertificateService;
    @Mock private OcspSigner ocspSigner;

    private OcspSignerManagementService service;
    private CryptoDeviceEntity vslotPrimary;
    private CryptoDeviceEntity vslotFailover;
    private String sampleCertPem;

    @BeforeEach
    void setUp() throws Exception {
        service = new OcspSignerManagementService(
                signerRepository, deviceRepository, signingCertRepository, signingCertificateService, ocspSigner);

        CryptoProviderEntity prov = CryptoProviderEntity.builder()
                .id(1L).code("softhsm2").name("SoftHSM v2").wrapperType("PKCS11J")
                .libraryPath("/usr/lib/softhsm/libsofthsm2.so").enabled(true).build();
        vslotPrimary = CryptoDeviceEntity.builder()
                .id(10L).deviceId("softhsm-primary").provider(prov).tokenLabel("ocsp-signing").slotListIndex(0).enabled(true).build();
        vslotFailover = CryptoDeviceEntity.builder()
                .id(11L).deviceId("softhsm-secondary").provider(prov).tokenLabel("ocsp-signing-2").slotListIndex(1).enabled(true).build();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        Instant now = Instant.now();
        var builder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=Incert Root CA,O=Incert,C=LU"),
                BigInteger.valueOf(777),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                new X500Name("CN=Incert OCSP Signer,O=Incert,C=LU"),
                kp.getPublic()
        );
        var holder = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate()));
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
        sampleCertPem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----";
    }

    @Test
    void fullSignerLifecycleWithMultipleVslotsCsrGenerationAndCertificateImport() {
        when(deviceRepository.findByDeviceId("softhsm-primary")).thenReturn(Optional.of(vslotPrimary));
        when(deviceRepository.findByDeviceId("softhsm-secondary")).thenReturn(Optional.of(vslotFailover));
        when(ocspSigner.listProviders()).thenReturn(List.of(
                new ProviderDeviceInfo("softhsm-primary", "PKCS11J", "/usr/lib/softhsm/libsofthsm2.so", null,
                        "ocsp-signing", 101L, "LOCKED", false, "LOCKED", List.of(), Map.of()),
                new ProviderDeviceInfo("softhsm-secondary", "PKCS11J", "/usr/lib/softhsm/libsofthsm2.so", null,
                        "ocsp-signing-2", 202L, "ACTIVE", true, "ACTIVE", List.of("ocsp-key-lu"), Map.of("ocsp-key-lu", "RSA"))
        ));

        AtomicReference<OcspSignerEntity> stored = new AtomicReference<>();
        when(signerRepository.save(any(OcspSignerEntity.class))).thenAnswer(inv -> {
            OcspSignerEntity e = inv.getArgument(0);
            if (e.getId() == null) e.setId(1L);
            stored.set(e);
            return e;
        });
        when(signerRepository.findById(1L)).thenAnswer(inv -> Optional.ofNullable(stored.get()));

        // 1. Create Signer with 2 ordered HSM Vslots (softhsm-primary = PRIMARY, softhsm-secondary = FAILOVER)
        SignerDto created = service.createSigner(new SignerRequest(
                "lu-root-signer",
                "Luxembourg Root OCSP Signer",
                "CN=Incert OCSP Signer,O=Incert,C=LU",
                "ocsp-key-lu",
                "RSA",
                3072,
                "SHA384withRSA",
                List.of("softhsm-primary", "softhsm-secondary")
        ));

        assertThat(created.id()).isEqualTo(1L);
        assertThat(created.status()).isEqualTo("DRAFT");
        assertThat(created.vslots()).hasSize(2);
        assertThat(created.vslots().get(0).deviceId()).isEqualTo("softhsm-primary");
        assertThat(created.vslots().get(0).role()).isEqualTo("PRIMARY");
        assertThat(created.vslots().get(1).deviceId()).isEqualTo("softhsm-secondary");
        assertThat(created.vslots().get(1).role()).isEqualTo("FAILOVER");
        assertThat(created.hasCsr()).isFalse();
        assertThat(created.hasCertificate()).isFalse();
        assertThat(service.getCertificate(1L)).isEmpty();
        assertThat(service.getCsr(1L, false)).isEmpty();

        // 2. POST /signer/1/csr -> automatically picks the ACTIVE failover Vslot when primary is LOCKED
        String fakeCsr = "-----BEGIN CERTIFICATE REQUEST-----\nMII-CSR...\n-----END CERTIFICATE REQUEST-----";
        when(signingCertificateService.generateCsr(any(GenerateCsrRequest.class))).thenReturn(
                new GenerateCsrResponse("softhsm-secondary", "ocsp-key-lu",
                        "CN=Incert OCSP Signer,O=Incert,C=LU", "RSA", fakeCsr));

        SignerCsrRequest.SignerCsrResponse csrRes = service.generateCsr(1L, null);
        assertThat(csrRes.vslotDeviceId()).isEqualTo("softhsm-secondary");
        assertThat(csrRes.csrPem()).isEqualTo(fakeCsr);
        assertThat(csrRes.signatureAlgorithm()).isEqualTo("SHA384withRSA");

        // GET /signer/1/csr now returns the stored CSR
        assertThat(service.getCsr(1L, false)).isPresent();
        assertThat(service.getCsr(1L, false).get().csrPem()).isEqualTo(fakeCsr);

        // 3. POST /signer/1/cert -> imports certificate and activates signer
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
        when(signerRepository.findAll()).thenReturn(List.of(stored.get()));

        SignerDto afterImport = service.importCertificate(1L, new SignerCertImportRequest(sampleCertPem, "SHA384withRSA", true));
        assertThat(afterImport.active()).isTrue();
        assertThat(afterImport.status()).isEqualTo("ACTIVE");
        assertThat(afterImport.hasCertificate()).isTrue();
        assertThat(afterImport.certificate().serialNumber()).isEqualTo("309");

        // 4. GET /signer/1/cert returns the imported certificate
        var certOpt = service.getCertificate(1L);
        assertThat(certOpt).isPresent();
        assertThat(certOpt.get().certificatePem()).contains("BEGIN CERTIFICATE");
        assertThat(certOpt.get().issuerDn()).contains("Incert Root CA");
    }

    @Test
    void createSignerAutoGeneratesUuidForCodeAndKeyLabelWhenOmitted() {
        when(deviceRepository.findByDeviceId("softhsm-primary")).thenReturn(Optional.of(vslotPrimary));
        when(ocspSigner.listProviders()).thenReturn(List.of());
        when(signerRepository.save(any(OcspSignerEntity.class))).thenAnswer(inv -> {
            OcspSignerEntity e = inv.getArgument(0);
            e.setId(2L);
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
    }
}

