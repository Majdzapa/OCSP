package lu.incert.ocsp.client.service;

import lu.incert.ocsp.client.config.OcspClientProperties;
import lu.incert.ocsp.client.dto.OcspCheckRequest;
import lu.incert.ocsp.client.dto.OcspCheckResult;
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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

@ExtendWith(MockitoExtension.class)
class OcspClientServiceTest {

    private RestClient.Builder restClientBuilder;
    private MockRestServiceServer mockServer;
    private OcspClientService clientService;

    private KeyPair caKeyPair;
    private X509Certificate caCert;
    private String caCertPem;

    @BeforeAll
    static void initBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        restClientBuilder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(restClientBuilder).build();

        OcspClientProperties clientProperties = new OcspClientProperties();
        clientProperties.setDefaultResponderUrl("http://localhost:8080/ocsp");
        clientProperties.setPkiDir("./target/test-pki");

        clientService = new OcspClientService(
                restClientBuilder,
                clientProperties
        );

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        caKeyPair = kpg.generateKeyPair();

        X500Name caName = new X500Name("CN=Test CA,O=Incert");
        BigInteger caSerial = BigInteger.ONE;
        Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(caKeyPair.getPrivate());

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                caName, caSerial, notBefore, notAfter, caName,
                SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded())
        );
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        X509CertificateHolder holder = builder.build(signer);
        caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);

        StringWriter sw = new StringWriter();
        try (org.bouncycastle.openssl.jcajce.JcaPEMWriter pw = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw)) {
            pw.writeObject(caCert);
        }
        caCertPem = sw.toString();
    }

    @Test
    void testHandlesMalformedResponseGracefully() {
        mockServer.expect(requestTo("http://localhost:8080/ocsp"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withStatus(HttpStatus.OK)
                        .contentType(MediaType.parseMediaType("application/ocsp-response"))
                        .body("this-is-not-valid-der-bytes".getBytes()));

        OcspCheckResult result = clientService.check(new OcspCheckRequest(
                "01ab23cd",
                null,
                caCertPem,
                false,
                "POST",
                "http://localhost:8080/ocsp"
        ));

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).contains("ASN.1 parse error");
    }

    @Test
    void testHandlesHttpErrorGracefully() {
        mockServer.expect(requestTo("http://localhost:8080/ocsp"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR)
                        .contentType(MediaType.parseMediaType("application/ocsp-response"))
                        .body(new byte[0]));

        OcspCheckResult result = clientService.check(new OcspCheckRequest(
                "01ab23cd",
                null,
                caCertPem,
                false,
                "POST",
                "http://localhost:8080/ocsp"
        ));

        assertThat(result.valid()).isFalse();
        assertThat(result.error()).isNotNull();
    }

    @Test
    void testUnknownStatusExplainsIssuerKeyHashMismatchWhenSerialExistsInDb() throws Exception {
        lu.incert.ocsp.status.service.CertificateStatusService statusService =
                org.mockito.Mockito.mock(lu.incert.ocsp.status.service.CertificateStatusService.class);
        RestClient.Builder diagBuilder = RestClient.builder();
        MockRestServiceServer diagServer = MockRestServiceServer.bindTo(diagBuilder).build();

        OcspClientProperties props = new OcspClientProperties();
        props.setDefaultResponderUrl("http://localhost:8080/ocsp");
        props.setPkiDir("./target/test-pki");
        OcspClientService diagClient = new OcspClientService(diagBuilder, props, statusService);

        BigInteger serial = new BigInteger("01ab23cd", 16);
        var digProv = new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        var caHolder = new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(caCert);
        var certId = new org.bouncycastle.cert.ocsp.CertificateID(
                digProv.get(org.bouncycastle.cert.ocsp.CertificateID.HASH_SHA1), caHolder, serial);

        // Build a valid signed OCSP response carrying UnknownStatus
        var respBuilder = new org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder(
                new org.bouncycastle.cert.ocsp.RespID(caHolder.getSubject()));
        Date now = new Date();
        respBuilder.addResponse(certId, new org.bouncycastle.cert.ocsp.UnknownStatus(),
                now, Date.from(now.toInstant().plus(1, ChronoUnit.HOURS)), null);
        ContentSigner ocspSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(caKeyPair.getPrivate());
        var basicResp = respBuilder.build(ocspSigner, new X509CertificateHolder[]{caHolder}, now);
        byte[] derResp = new org.bouncycastle.cert.ocsp.OCSPRespBuilder()
                .build(org.bouncycastle.cert.ocsp.OCSPRespBuilder.SUCCESSFUL, basicResp)
                .getEncoded();

        // Simulate KMS bug: DB has serial=GOOD with matching issuerNameHash, but issuerKeyHash = SHA-1(PublicKey.getEncoded())
        byte[] wrongSpkiKeyHash = java.security.MessageDigest.getInstance("SHA-1")
                .digest(caCert.getPublicKey().getEncoded());
        var dbRow = lu.incert.ocsp.status.entity.RevocationStatus.builder()
                .serialNumber(serial.toByteArray())
                .issuerNameHash(certId.getIssuerNameHash())
                .issuerKeyHash(wrongSpkiKeyHash)
                .status(lu.incert.ocsp.status.entity.CertificateStatus.GOOD)
                .build();
        org.mockito.Mockito.when(statusService.findAllBySerialBytes(serial.toByteArray()))
                .thenReturn(java.util.List.of(dbRow));

        diagServer.expect(requestTo("http://localhost:8080/ocsp"))
                .andExpect(method(HttpMethod.POST))
                .andRespond(withStatus(HttpStatus.OK)
                        .contentType(MediaType.parseMediaType("application/ocsp-response"))
                        .body(derResp));

        OcspCheckResult result = diagClient.check(new OcspCheckRequest(
                "01ab23cd", null, caCertPem, false, "POST", "http://localhost:8080/ocsp"));

        assertThat(result.certStatus()).isEqualTo("UNKNOWN");
        assertThat(result.unknownReason())
                .contains("exists in OCSP DB (DB status: GOOD)")
                .contains("Issuer Key Hash mismatches")
                .contains("SubjectPublicKeyInfo");
    }
}

