package lu.incert.ocsp.signing;


import lu.incert.ocsp.signing.service.SigningCertificateService;
import lu.incert.ocsp.signing.dto.AddSigningCertificateRequest;
import lu.incert.ocsp.signing.dto.GenerateCsrRequest;
import lu.incert.ocsp.signing.dto.GenerateCsrResponse;
import lu.incert.ocsp.signing.dto.HsmInfoDto;
import lu.incert.ocsp.signing.dto.SigningCertificateDto;
import lu.incert.ocsp.signing.usecase.FindSigningCertificateUseCase;
import lu.incert.ocsp.signing.entity.SigningCertificate;
import lu.incert.ocsp.signing.repository.SigningCertificateRepository;
import lu.incert.ocsp.signing.hsm.OcspSigner;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SigningCertificateServiceTest {

    @Mock
    private SigningCertificateRepository repository;

    @Mock
    private OcspSigner ocspSigner;

    private SigningCertificateService service;
    private String testCertPem;
    private X509CertificateHolder testHolder;

    @BeforeEach
    void setUp() throws Exception {
        service = new SigningCertificateService(
                repository,
                ocspSigner,
                event -> {
                    if (event instanceof SigningCertificateService.SigningConfigurationChangedEvent e) {
                        service.onSigningConfigurationChanged(e);
                    }
                },
                new FindSigningCertificateUseCase(repository)
        );

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X500Name name = new X500Name("CN=Test OCSP Signer,O=Incert,C=CH");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(30, ChronoUnit.DAYS));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name,
                SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
        );
        builder.addExtension(
                org.bouncycastle.asn1.x509.Extension.extendedKeyUsage,
                false,
                new org.bouncycastle.asn1.x509.ExtendedKeyUsage(org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_OCSPSigning)
        );

        testHolder = builder.build(signer);
        testCertPem = SigningCertificateService.toPem(testHolder);
    }

    @Test
    void addCertificate_missingOcspSigningEkuAndNotCa_throwsException() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Regular TLS Server,O=Incert,C=CH");
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                name, BigInteger.valueOf(999L),
                Date.from(Instant.now().minus(1, ChronoUnit.DAYS)),
                Date.from(Instant.now().plus(30, ChronoUnit.DAYS)),
                name, SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
        );
        String nonOcspPem = SigningCertificateService.toPem(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));

        when(repository.existsByAlias("tls-cert")).thenReturn(false);

        assertThatThrownBy(() -> service.addCertificate(
                new AddSigningCertificateRequest("tls-cert", "key", nonOcspPem, false)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("id-kp-OCSPSigning");
    }

    @Test
    void addCertificate_validPem_savesAndReturnsDto() {
        when(repository.existsByAlias("new-cert")).thenReturn(false);
        when(ocspSigner.getActiveKeyLabel()).thenReturn("ocsp-signing-key");
        when(repository.save(any(SigningCertificate.class))).thenAnswer(inv -> {
            SigningCertificate c = inv.getArgument(0);
            c.setId(10L);
            return c;
        });

        var req = new AddSigningCertificateRequest("new-cert", null, testCertPem, false);
        SigningCertificateDto dto = service.addCertificate(req);

        assertThat(dto).isNotNull();
        assertThat(dto.alias()).isEqualTo("new-cert");
        assertThat(dto.providerId()).isEqualTo("default");
        assertThat(dto.keyLabel()).isEqualTo("ocsp-signing-key");
        assertThat(dto.active()).isFalse();
        verify(ocspSigner).importCertificateToToken(eq("default"), eq("ocsp-signing-key"), any(X509CertificateHolder.class));
        verify(repository).save(any(SigningCertificate.class));
    }

    @Test
    void addCertificate_duplicateAlias_throwsException() {
        when(repository.existsByAlias("dup-cert")).thenReturn(true);

        var req = new AddSigningCertificateRequest("dup-cert", "key", testCertPem, false);
        assertThatThrownBy(() -> service.addCertificate(req))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("already exists");
    }

    @Test
    void activate_validId_deactivatesOthersAndUpdatesSigner() {
        SigningCertificate cert = SigningCertificate.builder()
                .id(5L)
                .alias("cert-5")
                .keyLabel("key-5")
                .certificatePem(testCertPem)
                .subjectDn("CN=Test")
                .issuerDn("CN=Test")
                .serialNumber("123")
                .notBefore(Instant.now().minus(1, ChronoUnit.DAYS))
                .notAfter(Instant.now().plus(20, ChronoUnit.DAYS))
                .signatureAlgorithm("SHA256withRSA")
                .active(false)
                .build();

        when(repository.findById(5L)).thenReturn(Optional.of(cert));
        when(repository.save(any(SigningCertificate.class))).thenAnswer(inv -> inv.getArgument(0));

        SigningCertificateDto result = service.activate(5L);

        assertThat(result.active()).isTrue();
        verify(ocspSigner).updateActiveCertificate(eq("default"), eq("key-5"), any(X509CertificateHolder.class), eq("SHA256withRSA"));
    }

    @Test
    void deactivate_lastActiveCertificate_throwsException() {
        SigningCertificate activeCert = SigningCertificate.builder()
                .id(1L)
                .alias("only-active")
                .active(true)
                .build();
        when(repository.findById(1L)).thenReturn(Optional.of(activeCert));
        when(repository.countByActiveTrue()).thenReturn(1L);

        assertThatThrownBy(() -> service.deactivate(1L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Cannot deactivate the last remaining active signing certificate");
    }

    @Test
    void deactivate_whenMultipleActive_deactivatesTargetAndFallsBackToRemaining() {
        SigningCertificate cert1 = SigningCertificate.builder()
                .id(1L).alias("ca1-signer").keyLabel("key-1").certificatePem(testCertPem)
                .signatureAlgorithm("SHA256withRSA").active(true).build();
        SigningCertificate cert2 = SigningCertificate.builder()
                .id(2L).alias("ca2-signer").keyLabel("key-2").certificatePem(testCertPem)
                .signatureAlgorithm("SHA256withRSA").active(true).build();

        when(repository.findById(2L)).thenReturn(Optional.of(cert2));
        when(repository.countByActiveTrue()).thenReturn(2L);
        when(repository.save(any(SigningCertificate.class))).thenAnswer(inv -> inv.getArgument(0));
        when(repository.findAllByActiveTrueOrderByActivatedAtDesc()).thenReturn(java.util.List.of(cert1));

        SigningCertificateDto dto = service.deactivate(2L);

        assertThat(dto.active()).isFalse();
        verify(ocspSigner).updateActiveCertificate(eq("default"), eq("key-1"), any(X509CertificateHolder.class), eq("SHA256withRSA"));
    }

    @Test
    void addCertificate_customSignatureAlgorithm_persistsChosenAlgorithm() {
        when(repository.existsByAlias("rsa-384")).thenReturn(false);
        when(repository.save(any(SigningCertificate.class))).thenAnswer(inv -> {
            SigningCertificate c = inv.getArgument(0);
            c.setId(11L);
            return c;
        });

        var req = new AddSigningCertificateRequest("rsa-384", "ocsp-signing-key", testCertPem, false, "SHA384withRSA");
        SigningCertificateDto dto = service.addCertificate(req);

        assertThat(dto.signatureAlgorithm()).isEqualTo("SHA384withRSA");
    }

    @Test
    void addCertificate_incompatibleAlgorithm_throwsException() {
        when(repository.existsByAlias("bad-alg")).thenReturn(false);

        var req = new AddSigningCertificateRequest("bad-alg", "ocsp-signing-key", testCertPem, false, "SHA256withECDSA");
        assertThatThrownBy(() -> service.addCertificate(req))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Unsupported or incompatible RSA signature algorithm");
    }

    @Test
    void delete_activeCertificate_throwsException() {
        SigningCertificate activeCert = SigningCertificate.builder()
                .id(1L)
                .alias("active-cert")
                .active(true)
                .build();

        when(repository.findById(1L)).thenReturn(Optional.of(activeCert));

        assertThatThrownBy(() -> service.delete(1L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Cannot delete the currently active signing certificate");
    }

    @Test
    void generateCsr_delegatesToOcspSigner() {
        when(ocspSigner.generateCsr("default", "key-2", "CN=OCSP Signer 2,O=Incert,C=CH", "RSA", 3072, null, false))
                .thenReturn("-----BEGIN CERTIFICATE REQUEST-----\nMII...\n-----END CERTIFICATE REQUEST-----\n");

        var req = new GenerateCsrRequest("key-2", "CN=OCSP Signer 2,O=Incert,C=CH", "RSA", 3072, false);
        GenerateCsrResponse res = service.generateCsr(req);

        assertThat(res.providerId()).isEqualTo("default");
        assertThat(res.keyLabel()).isEqualTo("key-2");
        assertThat(res.csrPem()).contains("BEGIN CERTIFICATE REQUEST");
        verify(ocspSigner).generateCsr("default", "key-2", "CN=OCSP Signer 2,O=Incert,C=CH", "RSA", 3072, null, false);
    }

    @Test
    void addAndCsrWithExplicitProviderIdRoutesToSelectedProvider() {
        when(ocspSigner.generateCsr("softhsm-secondary", "key-sec", "CN=Secondary,O=Incert,C=CH", "EC", 256, "SHA384withECDSA", false))
                .thenReturn("-----BEGIN CERTIFICATE REQUEST-----\nEC...\n-----END CERTIFICATE REQUEST-----\n");

        var csrReq = new GenerateCsrRequest("key-sec", "CN=Secondary,O=Incert,C=CH", "EC", 256, false, "softhsm-secondary", "SHA384withECDSA");
        GenerateCsrResponse csrRes = service.generateCsr(csrReq);

        assertThat(csrRes.providerId()).isEqualTo("softhsm-secondary");
        verify(ocspSigner).generateCsr("softhsm-secondary", "key-sec", "CN=Secondary,O=Incert,C=CH", "EC", 256, "SHA384withECDSA", false);

        when(repository.existsByAlias("sec-cert")).thenReturn(false);
        when(repository.save(any(SigningCertificate.class))).thenAnswer(inv -> {
            SigningCertificate c = inv.getArgument(0);
            c.setId(22L);
            return c;
        });

        var addReq = new AddSigningCertificateRequest(
                "sec-cert", "key-sec", testCertPem, false, "SHA256withRSA", "softhsm-secondary");
        SigningCertificateDto saved = service.addCertificate(addReq);

        assertThat(saved.providerId()).isEqualTo("softhsm-secondary");
        verify(ocspSigner).importCertificateToToken(eq("softhsm-secondary"), eq("key-sec"), any(X509CertificateHolder.class));
    }

    @Test
    void getHsmInfo_returnsTokenDetails() {
        when(ocspSigner.type()).thenReturn("SOFTWARE");
        when(ocspSigner.getActiveKeyLabel()).thenReturn("ocsp-signing-key");
        when(ocspSigner.listKeyLabels()).thenReturn(java.util.List.of("ocsp-signing-key", "key-2"));

        HsmInfoDto info = service.getHsmInfo();

        assertThat(info.signerType()).isEqualTo("SOFTWARE");
        assertThat(info.tokenAliases()).containsExactly("ocsp-signing-key", "key-2");
    }
}

