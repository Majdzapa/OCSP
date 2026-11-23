package com.company.incert.pkcs11j;

import com.company.incert.pkcs11j.provider.Pkcs11Provider;
import com.company.incert.pkcs11j.provider.Pkcs11ProviderConfig;
import com.company.incert.pkcs11j.provider.PkcsProviders;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end JNI integration test exercising real {@code libpkcs11j} -> {@code libsofthsm2.so}:
 * {@code C_Initialize}, multi-slot resolution, {@code C_OpenSession}, {@code C_Login},
 * {@code C_GenerateKeyPair} (RSA &amp; EC), {@code C_SignInit}, {@code C_Sign} (including PSS &amp; ECDSA),
 * {@code C_CreateObject}, concurrent session pooling, and {@code C_Finalize}.
 */
class Pkcs11jSoftHsmIntegrationTest {

    private static String softhsmLib;
    private static Path confFile;

    @BeforeAll
    static void setupSoftHsmTokens() throws Exception {
        softhsmLib = findSoftHsmLibrary();
        Assumptions.assumeTrue(softhsmLib != null, "SoftHSM2 library not installed");

        String envConf = System.getenv("SOFTHSM2_CONF");
        Assumptions.assumeTrue(envConf != null && !envConf.isBlank(), "SOFTHSM2_CONF must be set");

        confFile = Path.of(envConf);
        Path baseDir = confFile.getParent();
        Path tokenDir = baseDir.resolve("tokens");
        if (Files.exists(baseDir)) {
            try (Stream<Path> walk = Files.walk(baseDir)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (IOException ignored) {}
                });
            }
        }
        Files.createDirectories(tokenDir);
        Files.writeString(confFile, "directories.tokendir = " + tokenDir.toAbsolutePath() + "\nobjectstore.backend = file\n");

        initToken("pkcs11j-dev-1");
        initToken("pkcs11j-dev-2");
    }

    @Test
    void multiDeviceSigningAndCsrVerificationViaNativeJni() throws Exception {
        try (PkcsProviders providers = new PkcsProviders()) {
            Pkcs11Provider dev1 = providers.register(new Pkcs11ProviderConfig(
                    "softhsm-1", softhsmLib, "pkcs11j-dev-1", null, 0, "1234".toCharArray(), 4, false));
            Pkcs11Provider dev2 = providers.register(new Pkcs11ProviderConfig(
                    "softhsm-2", softhsmLib, "pkcs11j-dev-2", null, 0, "1234".toCharArray(), 4, false));

            assertThat(providers.loadedModuleCount()).isEqualTo(1);
            assertThat(dev1.getTokenInfo().label()).isEqualTo("pkcs11j-dev-1");
            assertThat(dev2.getTokenInfo().label()).isEqualTo("pkcs11j-dev-2");

            // 1. Device 1: Generate RSA-2048 keypair & CSR
            String rsaCsrPem = dev1.generateCsr(
                    "ocsp-rsa-key", "CN=OCSP RSA Signer,O=Incert,C=CH", "RSA", 2048, false);
            PKCS10CertificationRequest rsaCsr = parseCsr(rsaCsrPem);
            PublicKey rsaPub = new JcaPEMKeyConverter().getPublicKey(rsaCsr.getSubjectPublicKeyInfo());
            ContentVerifierProvider rsaVerifier = new JcaContentVerifierProviderBuilder().build(rsaPub);
            assertThat(rsaCsr.isSignatureValid(rsaVerifier)).isTrue();

            // 2. Device 2: Generate EC P-256 keypair & CSR
            String ecCsrPem = dev2.generateCsr(
                    "ocsp-ec-key", "CN=OCSP EC Signer,O=Incert,C=CH", "EC", 256, false);
            PKCS10CertificationRequest ecCsr = parseCsr(ecCsrPem);
            PublicKey ecPub = new JcaPEMKeyConverter().getPublicKey(ecCsr.getSubjectPublicKeyInfo());
            ContentVerifierProvider ecVerifier = new JcaContentVerifierProviderBuilder().build(ecPub);
            assertThat(ecCsr.isSignatureValid(ecVerifier)).isTrue();

            // Verify key isolation per token
            assertThat(dev1.listKeyLabels()).containsExactly("ocsp-rsa-key");
            assertThat(dev2.listKeyLabels()).containsExactly("ocsp-ec-key");
            assertThat(dev2.listKeys().get(0).keyAlgorithm()).isEqualTo("EC");
            assertThat(dev2.listKeys().get(0).keySizeBits()).isEqualTo(256);

            // 3. Issue self-signed/CA-signed cert for Device 1 key and import via C_CreateObject
            KeyPairGenerator caKpg = KeyPairGenerator.getInstance("RSA");
            caKpg.initialize(2048);
            KeyPair caKp = caKpg.generateKeyPair();
            Instant now = Instant.now();
            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    new X500Name("CN=Test CA,O=Incert,C=CH"),
                    BigInteger.valueOf(1001L),
                    Date.from(now.minus(1, ChronoUnit.HOURS)),
                    Date.from(now.plus(30, ChronoUnit.DAYS)),
                    rsaCsr.getSubject(),
                    rsaCsr.getSubjectPublicKeyInfo());
            X509CertificateHolder issuedCert = certBuilder.build(
                    new JcaContentSignerBuilder("SHA256withRSA").build(caKp.getPrivate()));
            dev1.importCertificate("ocsp-rsa-key", issuedCert);

            // 4. Sign with SHA256withRSA, SHA256withRSAandMGF1, and SHA256withECDSA and verify via JCA
            byte[] payload = "RFC6960-OCSP-BasicResponse-TBS-Payload".getBytes(StandardCharsets.UTF_8);

            byte[] rsaSig = dev1.sign("ocsp-rsa-key", "SHA256withRSA", payload);
            Signature jcaRsa = Signature.getInstance("SHA256withRSA");
            jcaRsa.initVerify(rsaPub);
            jcaRsa.update(payload);
            assertThat(jcaRsa.verify(rsaSig)).isTrue();

            byte[] pssSig = dev1.sign("ocsp-rsa-key", "SHA256withRSAandMGF1", payload);
            Signature jcaPss = Signature.getInstance("SHA256withRSAandMGF1", new BouncyCastleProvider());
            jcaPss.initVerify(rsaPub);
            jcaPss.update(payload);
            assertThat(jcaPss.verify(pssSig)).isTrue();

            byte[] ecSig = dev2.sign("ocsp-ec-key", "SHA256withECDSA", payload);
            Signature jcaEc = Signature.getInstance("SHA256withECDSA");
            jcaEc.initVerify(ecPub);
            jcaEc.update(payload);
            assertThat(jcaEc.verify(ecSig)).isTrue();

            // 5. Exercise concurrent session pool across both devices simultaneously
            ExecutorService pool = Executors.newFixedThreadPool(8);
            try {
                List<Callable<Boolean>> tasks = java.util.stream.IntStream.range(0, 24)
                        .<Callable<Boolean>>mapToObj(i -> () -> {
                            byte[] data = ("concurrent-" + i).getBytes(StandardCharsets.UTF_8);
                            if (i % 2 == 0) {
                                byte[] s = dev1.sign("ocsp-rsa-key", "SHA256withRSA", data);
                                Signature v = Signature.getInstance("SHA256withRSA");
                                v.initVerify(rsaPub);
                                v.update(data);
                                return v.verify(s);
                            } else {
                                byte[] s = dev2.sign("ocsp-ec-key", "SHA256withECDSA", data);
                                Signature v = Signature.getInstance("SHA256withECDSA");
                                v.initVerify(ecPub);
                                v.update(data);
                                return v.verify(s);
                            }
                        })
                        .toList();
                for (Future<Boolean> f : pool.invokeAll(tasks)) {
                    assertThat(f.get()).isTrue();
                }
            } finally {
                pool.shutdownNow();
            }
        }
    }

    private static PKCS10CertificationRequest parseCsr(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            return (PKCS10CertificationRequest) parser.readObject();
        }
    }

    private static void initToken(String label) throws Exception {
        String softhsmUtil = findSoftHsmUtil();
        Assumptions.assumeTrue(softhsmUtil != null, "softhsm2-util not found");
        ProcessBuilder pb = new ProcessBuilder(
                softhsmUtil, "--init-token", "--free", "--label", label, "--so-pin", "12345678", "--pin", "1234");
        pb.environment().put("SOFTHSM2_CONF", confFile.toAbsolutePath().toString());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int exit = p.waitFor();
        assertThat(exit).withFailMessage("softhsm2-util failed (%d): %s", exit, output).isEqualTo(0);
    }

    private static String findSoftHsmLibrary() {
        for (String candidate : List.of(
                "/opt/homebrew/lib/softhsm/libsofthsm2.so",
                "/usr/lib/softhsm/libsofthsm2.so",
                "/usr/local/lib/softhsm/libsofthsm2.so")) {
            if (Files.exists(Path.of(candidate))) {
                return candidate;
            }
        }
        return null;
    }

    private static String findSoftHsmUtil() {
        for (String candidate : List.of(
                "/opt/homebrew/bin/softhsm2-util",
                "/usr/bin/softhsm2-util",
                "/usr/local/bin/softhsm2-util")) {
            if (Files.exists(Path.of(candidate))) {
                return candidate;
            }
        }
        return null;
    }
}
