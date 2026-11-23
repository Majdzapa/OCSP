package com.company.incert.ocsp.trust;

import com.company.incert.ocsp.trust.entity.TrustedCaEntity;
import com.company.incert.ocsp.trust.repository.TrustedCaRepository;
import com.company.incert.ocsp.trust.service.TrustedCaService;
import com.company.incert.ocsp.trust.tls.HotReloadableTrustManager;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HotReloadableTrustManagerTest {

    @Mock
    private TrustedCaRepository repository;

    @BeforeAll
    static void initBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Test
    void trustManagerHotReloadsAcceptedIssuersAndValidatesClientChainWithoutRestart() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKp = kpg.generateKeyPair();
        KeyPair userKp = kpg.generateKeyPair();

        Date now = Date.from(Instant.now().minus(1, ChronoUnit.HOURS));
        Date later = Date.from(Instant.now().plus(30, ChronoUnit.DAYS));

        X509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=Native TLS Root CA"), BigInteger.ONE, now, later,
                new X500Name("CN=Native TLS Root CA"), caKp.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner caSigner = new JcaContentSignerBuilder("SHA256withRSA").build(caKp.getPrivate());
        X509Certificate caCert = new JcaX509CertificateConverter().getCertificate(caBuilder.build(caSigner));

        X509v3CertificateBuilder userBuilder = new JcaX509v3CertificateBuilder(
                new X500Name("CN=Native TLS Root CA"), BigInteger.TWO, now, later,
                new X500Name("CN=bob"), userKp.getPublic());
        X509Certificate userCert = new JcaX509CertificateConverter().getCertificate(userBuilder.build(caSigner));

        String caPem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(caCert.getEncoded())
                + "\n-----END CERTIFICATE-----";

        TrustedCaService caService = new TrustedCaService(repository);
        HotReloadableTrustManager trustManager = new HotReloadableTrustManager(caService);

        // Before CA import: empty issuers and rejected
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
        assertThatThrownBy(() -> trustManager.checkClientTrusted(new X509Certificate[]{userCert}, "RSA"))
                .isInstanceOf(CertificateException.class);

        when(repository.existsByAliasIgnoreCase("native-root")).thenReturn(false);
        when(repository.existsByFingerprintSha256(any())).thenReturn(false);
        when(repository.save(any())).thenAnswer(inv -> {
            TrustedCaEntity saved = inv.getArgument(0);
            when(repository.findByEnabledTrue()).thenReturn(List.of(saved));
            return saved;
        });

        caService.importTrustedCa("native-root", caPem);

        // Immediately after import (zero restart): issuer advertised and client chain accepted
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThatCode(() -> trustManager.checkClientTrusted(new X509Certificate[]{userCert}, "RSA"))
                .doesNotThrowAnyException();
    }
}

