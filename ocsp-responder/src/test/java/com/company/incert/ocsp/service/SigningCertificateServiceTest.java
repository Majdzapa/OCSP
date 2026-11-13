package com.company.incert.ocsp.service;

import com.company.incert.ocsp.dto.AddSigningCertificateRequest;
import com.company.incert.ocsp.dto.SigningCertificateDto;
import com.company.incert.ocsp.entity.SigningCertificate;
import com.company.incert.ocsp.repository.SigningCertificateRepository;
import com.company.incert.ocsp.signing.OcspSigner;
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
        service = new SigningCertificateService(repository, ocspSigner);

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

        testHolder = builder.build(signer);
        testCertPem = SigningCertificateService.toPem(testHolder);
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
        assertThat(dto.keyLabel()).isEqualTo("ocsp-signing-key");
        assertThat(dto.active()).isFalse();
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
        verify(repository).deactivateAll();
        verify(ocspSigner).updateActiveCertificate(eq("key-5"), any(X509CertificateHolder.class));
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
}

