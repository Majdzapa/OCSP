package com.company.incert.ocsp.service;

import com.company.incert.ocsp.dto.OcspCheckRequest;
import com.company.incert.ocsp.dto.OcspCheckResult;
import com.company.incert.ocsp.entity.CertificateStatus;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.signing.SoftwareKeyOcspSigner;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

@ExtendWith(MockitoExtension.class)
class OcspClientServiceTest {

    private static KeyPair caKeyPair;
    private static X509Certificate caCert;
    private static X509CertificateHolder caCertHolder;

    private static KeyPair signerKeyPair;
    private static X509Certificate signerCert;
    private static X509CertificateHolder signerCertHolder;

    private static KeyPair eeKeyPair;
    private static X509Certificate eeCert;

    @Mock
    private CertificateStatusService statusService;

    private OcspResponderService responderService;
    private OcspClientService clientService;
    private MockRestServiceServer mockServer;

    @BeforeAll
    static void initCrypto() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        caKeyPair = kpg.generateKeyPair();
        signerKeyPair = kpg.generateKeyPair();
        eeKeyPair = kpg.generateKeyPair();

        // 1. Root / Intermediate CA
        X500Name caName = new X500Name("CN=Incert Test CA,O=Incert,C=CH");
        Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));
        ContentSigner caSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caKeyPair.getPrivate());

        X509v3CertificateBuilder caBuilder = new X509v3CertificateBuilder(
            caName, BigInteger.ONE, notBefore, notAfter, caName,
            SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded())
        );
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caCertHolder = caBuilder.build(caSigner);
        caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caCertHolder);

        // 2. Delegated OCSP Signer (issued by CA, with id-kp-OCSPSigning EKU)
        X500Name signerName = new X500Name("CN=Incert Delegated OCSP Signer,O=Incert,C=CH");
        X509v3CertificateBuilder signerBuilder = new X509v3CertificateBuilder(
            caName, BigInteger.valueOf(2), notBefore, notAfter, signerName,
            SubjectPublicKeyInfo.getInstance(signerKeyPair.getPublic().getEncoded())
        );
        signerBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        signerBuilder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));
        signerCertHolder = signerBuilder.build(caSigner);
        signerCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(signerCertHolder);

        // 3. End-Entity Cert
        X500Name eeName = new X500Name("CN=ee-test.incert.ch,O=Incert,C=CH");
        X509v3CertificateBuilder eeBuilder = new X509v3CertificateBuilder(
            caName, BigInteger.valueOf(98765), notBefore, notAfter, eeName,
            SubjectPublicKeyInfo.getInstance(eeKeyPair.getPublic().getEncoded())
        );
        eeBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        eeCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(eeBuilder.build(caSigner));
    }

    @BeforeEach
    void setUp() {
        SoftwareKeyOcspSigner signer = new SoftwareKeyOcspSigner(
            signerKeyPair.getPrivate(),
            new X509CertificateHolder[]{signerCertHolder, caCertHolder},
            Instant.now().plus(30, ChronoUnit.DAYS)
        );
        responderService = new OcspResponderService(statusService, signer, new SimpleMeterRegistry(), Duration.ofHours(24));

        RestClient.Builder builder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(builder).build();
        clientService = new OcspClientService(statusService, builder, "http://localhost:8080/ocsp", "/non-existent");
    }

    @Test
    void shouldVerifyGoodCertificateEndToEnd() throws Exception {
        when(statusService.findByCertId(any(), any(), any())).thenReturn(Optional.of(
            RevocationStatus.builder()
                .issuerNameHash(new byte[20])
                .issuerKeyHash(new byte[20])
                .serialNumber(eeCert.getSerialNumber().toByteArray())
                .status(CertificateStatus.GOOD)
                .thisUpdate(Instant.now())
                .sequence(1)
                .build()
        ));

        // Intercept POST http://localhost:8080/ocsp and route to our responderService
        mockServer.expect(requestTo("http://localhost:8080/ocsp"))
            .andExpect(method(HttpMethod.POST))
            .andRespond(request -> {
                byte[] reqBytes = ((org.springframework.mock.http.client.MockClientHttpRequest) request).getBodyAsBytes();
                byte[] respBytes = responderService.handle(reqBytes);
                org.springframework.mock.http.client.MockClientHttpResponse response =
                    new org.springframework.mock.http.client.MockClientHttpResponse(respBytes, HttpStatus.OK);
                response.getHeaders().setContentType(MediaType.parseMediaType("application/ocsp-response"));
                return response;
            });

        String certPem = toPem(eeCert);
        String caPem = toPem(caCert);

        OcspCheckResult result = clientService.check(new OcspCheckRequest(
            null,
            certPem,
            caPem,
            true, // with nonce
            "POST",
            "http://localhost:8080/ocsp"
        ));

        assertThat(result.valid()).isTrue();
        assertThat(result.certStatus()).isEqualTo("GOOD");
        assertThat(result.responseStatus()).isEqualTo("SUCCESSFUL");
        assertThat(result.nonceSent()).isNotBlank();
        assertThat(result.nonceEchoed()).isEqualTo(result.nonceSent());
        assertThat(result.checks()).allMatch(c -> c.outcome() != OcspCheckResult.Outcome.FAIL);
    }

    private static String toPem(X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        try (org.bouncycastle.openssl.jcajce.JcaPEMWriter pw = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw)) {
            pw.writeObject(cert);
        }
        return sw.toString();
    }
}
