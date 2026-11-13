package com.company.incert.ocsp.service;

import com.company.incert.ocsp.entity.CertificateStatus;
import com.company.incert.ocsp.entity.RevocationReason;
import com.company.incert.ocsp.entity.RevocationStatus;
import com.company.incert.ocsp.signing.SoftwareKeyOcspSigner;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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

@ExtendWith(MockitoExtension.class)
class OcspResponderServiceTest {

    private static KeyPair caKeyPair;
    private static X509CertificateHolder caCertHolder;

    @Mock
    private CertificateStatusService statusService;

    private SoftwareKeyOcspSigner signer;
    private SimpleMeterRegistry meterRegistry;
    private OcspResponderService service;

    @BeforeAll
    static void initCrypto() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        caKeyPair = kpg.generateKeyPair();

        X500Name name = new X500Name("CN=Test CA,O=Incert,C=CH");
        BigInteger serial = BigInteger.ONE;
        Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));

        ContentSigner cs = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caKeyPair.getPrivate());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            name, serial, notBefore, notAfter, name,
            SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded())
        );
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caCertHolder = builder.build(cs);
    }

    @BeforeEach
    void setUp() {
        meterRegistry = new SimpleMeterRegistry();
        signer = new SoftwareKeyOcspSigner(
            caKeyPair.getPrivate(),
            new X509CertificateHolder[]{caCertHolder},
            Instant.now().plus(30, ChronoUnit.DAYS)
        );
        service = new OcspResponderService(statusService, signer, meterRegistry, Duration.ofHours(24));
    }

    @Test
    void shouldReturnGoodStatusForValidCertificate() throws Exception {
        BigInteger targetSerial = BigInteger.valueOf(12345);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), caCertHolder, targetSerial);

        when(statusService.findByCertId(any(), any(), any())).thenReturn(Optional.of(
            RevocationStatus.builder()
                .issuerNameHash(certId.getIssuerNameHash())
                .issuerKeyHash(certId.getIssuerKeyHash())
                .serialNumber(targetSerial.toByteArray())
                .status(CertificateStatus.GOOD)
                .thisUpdate(Instant.now())
                .sequence(1)
                .build()
        ));

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        reqBuilder.addRequest(certId);
        byte[] requestBytes = reqBuilder.build().getEncoded();

        byte[] responseBytes = service.handle(requestBytes);
        assertThat(responseBytes).isNotEmpty();

        OCSPResp response = new OCSPResp(responseBytes);
        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);

        BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
        SingleResp singleResp = basicResp.getResponses()[0];
        assertThat(singleResp.getCertStatus()).isEqualTo(org.bouncycastle.cert.ocsp.CertificateStatus.GOOD);
    }

    @Test
    void shouldReturnRevokedStatusForRevokedCertificate() throws Exception {
        BigInteger targetSerial = BigInteger.valueOf(99999);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), caCertHolder, targetSerial);

        when(statusService.findByCertId(any(), any(), any())).thenReturn(Optional.of(
            RevocationStatus.builder()
                .issuerNameHash(certId.getIssuerNameHash())
                .issuerKeyHash(certId.getIssuerKeyHash())
                .serialNumber(targetSerial.toByteArray())
                .status(CertificateStatus.REVOKED)
                .revocationTime(Instant.now().minus(1, ChronoUnit.HOURS))
                .revocationReason(RevocationReason.KEY_COMPROMISE.name())
                .thisUpdate(Instant.now())
                .sequence(2)
                .build()
        ));

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        reqBuilder.addRequest(certId);
        byte[] responseBytes = service.handle(reqBuilder.build().getEncoded());

        OCSPResp response = new OCSPResp(responseBytes);
        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);

        BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
        SingleResp singleResp = basicResp.getResponses()[0];
        assertThat(singleResp.getCertStatus()).isInstanceOf(RevokedStatus.class);
    }

    @Test
    void shouldReturnUnknownStatusWhenNotFound() throws Exception {
        BigInteger targetSerial = BigInteger.valueOf(77777);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), caCertHolder, targetSerial);

        when(statusService.findByCertId(any(), any(), any())).thenReturn(Optional.empty());

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        reqBuilder.addRequest(certId);
        byte[] responseBytes = service.handle(reqBuilder.build().getEncoded());

        OCSPResp response = new OCSPResp(responseBytes);
        BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
        SingleResp singleResp = basicResp.getResponses()[0];
        assertThat(singleResp.getCertStatus()).isInstanceOf(UnknownStatus.class);
    }

    @Test
    void shouldEchoNonceWhenProvided() throws Exception {
        BigInteger targetSerial = BigInteger.valueOf(55555);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), caCertHolder, targetSerial);

        when(statusService.findByCertId(any(), any(), any())).thenReturn(Optional.empty());

        byte[] nonce = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        reqBuilder.addRequest(certId);
        reqBuilder.setRequestExtensions(new Extensions(new Extension(
            OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
            false,
            new DEROctetString(nonce)
        )));

        byte[] responseBytes = service.handle(reqBuilder.build().getEncoded());
        BasicOCSPResp basicResp = (BasicOCSPResp) new OCSPResp(responseBytes).getResponseObject();
        Extension echoedNonce = basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        assertThat(echoedNonce).isNotNull();
    }
}

