package com.company.incert.ocsp.responder.application.service;

import com.company.incert.ocsp.shared.domain.CertId;
import com.company.incert.ocsp.shared.domain.CertificateStatus;
import com.company.incert.ocsp.shared.domain.RevocationReason;
import com.company.incert.ocsp.signing.adapter.out.SoftwareKeyOcspSigner;
import com.company.incert.ocsp.status.application.port.in.LookupStatusUseCase;
import com.company.incert.ocsp.shared.CertificateStatusRecord;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class OcspRequestHandlerServiceTest {

    private static KeyPair caKeyPair;
    private static X509Certificate caCert;
    private static X509CertificateHolder caCertHolder;

    private SoftwareKeyOcspSigner signer;
    private SimpleMeterRegistry meterRegistry;

    @BeforeAll
    static void initBouncyCastle() throws Exception {
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
        caCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(caCertHolder);
    }

    @BeforeEach
    void setUp() throws Exception {
        meterRegistry = new SimpleMeterRegistry();
        signer = new SoftwareKeyOcspSigner(
            caKeyPair.getPrivate(),
            new X509CertificateHolder[]{caCertHolder},
            Instant.now().plus(30, ChronoUnit.DAYS)
        );
    }

    @Test
    void shouldReturnGoodStatusForValidCertificate() throws Exception {
        BigInteger targetSerial = BigInteger.valueOf(12345);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), caCertHolder, targetSerial);

        LookupStatusUseCase statusLookup = id -> Optional.of(new CertificateStatusRecord(
            id.issuerNameHash(), id.issuerKeyHash(), id.serialNumber(),
            CertificateStatus.GOOD, null, null,
            Instant.now(), "event-1", 1
        ));

        OcspRequestHandlerService service = new OcspRequestHandlerService(statusLookup, signer, meterRegistry);

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

        LookupStatusUseCase statusLookup = id -> Optional.of(new CertificateStatusRecord(
            id.issuerNameHash(), id.issuerKeyHash(), id.serialNumber(),
            CertificateStatus.REVOKED, Instant.now().minus(1, ChronoUnit.HOURS), RevocationReason.KEY_COMPROMISE,
            Instant.now(), "event-2", 2
        ));

        OcspRequestHandlerService service = new OcspRequestHandlerService(statusLookup, signer, meterRegistry);

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        reqBuilder.addRequest(certId);
        byte[] requestBytes = reqBuilder.build().getEncoded();

        byte[] responseBytes = service.handle(requestBytes);
        OCSPResp response = new OCSPResp(responseBytes);
        assertThat(response.getStatus()).isEqualTo(OCSPRespBuilder.SUCCESSFUL);

        BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
        SingleResp singleResp = basicResp.getResponses()[0];
        assertThat(singleResp.getCertStatus()).isInstanceOf(RevokedStatus.class);
    }

    @Test
    void shouldReturnUnknownStatusForMissingCertificate() throws Exception {
        BigInteger targetSerial = BigInteger.valueOf(55555);
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1), caCertHolder, targetSerial);

        LookupStatusUseCase statusLookup = id -> Optional.empty();

        OcspRequestHandlerService service = new OcspRequestHandlerService(statusLookup, signer, meterRegistry);

        OCSPReqBuilder reqBuilder = new OCSPReqBuilder();
        reqBuilder.addRequest(certId);
        byte[] requestBytes = reqBuilder.build().getEncoded();

        byte[] responseBytes = service.handle(requestBytes);
        OCSPResp response = new OCSPResp(responseBytes);
        BasicOCSPResp basicResp = (BasicOCSPResp) response.getResponseObject();
        SingleResp singleResp = basicResp.getResponses()[0];
        assertThat(singleResp.getCertStatus()).isInstanceOf(UnknownStatus.class);
    }
}
