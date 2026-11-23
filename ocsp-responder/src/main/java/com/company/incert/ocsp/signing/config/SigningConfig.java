package com.company.incert.ocsp.signing.config;

import com.company.incert.hsm.grpc.v1.ListProvidersResponse;
import com.company.incert.hsm.grpc.v1.ProviderDescriptor;
import com.company.incert.ocsp.signing.hsm.MultiProviderOcspSigner;
import com.company.incert.ocsp.signing.hsm.OcspSigner;
import com.company.incert.ocsp.signing.hsm.Pkcs11OcspSigner;
import com.company.incert.ocsp.signing.hsm.SoftwareKeyOcspSigner;
import com.company.incert.ocsp.signing.provider.GrpcCryptoProviderAdapter;
import com.company.incert.ocsp.signing.provider.GrpcHsmClient;
import com.company.incert.ocsp.signing.provider.PkcsProviders;
import com.company.incert.ocsp.signing.provider.SunPkcs11CryptoProviderAdapter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.ResourceLoader;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Configures {@link PkcsProviders} and the {@link OcspSigner} port:
 * <ul>
 *   <li>{@code hsm.enabled=true, hsm.mode=GRPC}: connects to one or more {@code hsm-signer} gRPC daemons
 *       exposing multiple PKCS11J hardware/software devices simultaneously.</li>
 *   <li>{@code hsm.enabled=true, hsm.mode=SUN_PKCS11}: loads local PKCS#11 token(s) via SunPKCS11.</li>
 *   <li>{@code hsm.enabled=false} (non-prod only): in-memory software fallback signer.</li>
 * </ul>
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class SigningConfig {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final HsmProperties hsm;
    private final ResourceLoader resourceLoader;

    @Bean(destroyMethod = "close")
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true", matchIfMissing = true)
    public PkcsProviders pkcsProviders() {
        PkcsProviders providers = new PkcsProviders();
        String mode = hsm.getMode() != null ? hsm.getMode().trim().toUpperCase() : "SUN_PKCS11";

        if ("GRPC".equals(mode)) {
            configureGrpcProviders(providers);
        } else {
            String primaryId = (hsm.getDefaultProviderId() != null && !hsm.getDefaultProviderId().isBlank())
                    ? hsm.getDefaultProviderId().trim()
                    : "default";
            log.info("Connecting local SunPKCS11 provider '{}': library={}, token={}, slotIndex={}",
                    primaryId, hsm.getPkcs11Library(), hsm.getTokenLabel(), hsm.getSlotIndex());
            Pkcs11OcspSigner primary = new Pkcs11OcspSigner(
                    hsm.getPkcs11Library(), hsm.getTokenLabel(), hsm.getPin(),
                    hsm.getKeyLabel(), hsm.getSlotIndex(), hsm.getConfigPath());
            providers.register(new SunPkcs11CryptoProviderAdapter(primaryId, primary));
        }

        registerLocalDevices(providers);

        if (hsm.getDefaultProviderId() != null && !hsm.getDefaultProviderId().isBlank()
                && providers.listProviderIds().contains(hsm.getDefaultProviderId().trim())) {
            providers.setDefaultProviderId(hsm.getDefaultProviderId().trim());
        }

        log.info("PkcsProviders ready with {} device(s): {} (default={})",
                providers.listProviderIds().size(),
                providers.listProviderIds(),
                providers.getDefaultProviderId());
        return providers;
    }

    @Bean
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "true", matchIfMissing = true)
    public OcspSigner multiProviderOcspSigner(PkcsProviders pkcsProviders) {
        return new MultiProviderOcspSigner(pkcsProviders, hsm.getKeyLabel());
    }

    private void configureGrpcProviders(PkcsProviders providers) {
        List<HsmProperties.GrpcClientProperties> targets = new ArrayList<>();
        HsmProperties.GrpcClientProperties primary = hsm.getGrpc();
        if (primary != null && primary.getHost() != null && !primary.getHost().isBlank()) {
            targets.add(primary);
        }
        if (primary != null && primary.getEndpoints() != null) {
            targets.addAll(primary.getEndpoints());
        }
        if (targets.isEmpty()) {
            throw new IllegalStateException("hsm.mode=GRPC requires hsm.grpc.host/port or hsm.grpc.endpoints");
        }

        String remoteSuggestedDefault = null;
        for (HsmProperties.GrpcClientProperties endpoint : targets) {
            GrpcHsmClient client = new GrpcHsmClient(
                    endpoint.getHost(),
                    endpoint.getPort(),
                    endpoint.getTimeoutSeconds(),
                    endpoint.isTlsEnabled(),
                    endpoint.getKeyStore(),
                    endpoint.getKeyStorePassword(),
                    endpoint.getTrustStore(),
                    endpoint.getTrustStorePassword(),
                    resourceLoader);
            providers.trackManagedClient(client);

            ListProvidersResponse resp = fetchProvidersWithRetry(client, endpoint.getHost(), endpoint.getPort());
            String prefix = (endpoint.getIdPrefix() != null && !endpoint.getIdPrefix().isBlank())
                    ? endpoint.getIdPrefix().trim() + "-"
                    : "";

            for (ProviderDescriptor pd : resp.getProvidersList()) {
                String localId = prefix + pd.getProviderId();
                providers.register(new GrpcCryptoProviderAdapter(localId, pd.getProviderId(), client, pd));
                log.info("Discovered remote PKCS11J device '{}' on gRPC {}:{} (token='{}', slotId={}, healthy={})",
                        localId, endpoint.getHost(), endpoint.getPort(), pd.getTokenLabel(), pd.getSlotId(), pd.getHealthy());
            }

            if (remoteSuggestedDefault == null && !resp.getDefaultProviderId().isBlank()) {
                remoteSuggestedDefault = prefix + resp.getDefaultProviderId();
            }
        }

        if (providers.listProviderIds().isEmpty()) {
            throw new IllegalStateException("No PKCS11J signing devices discovered over gRPC");
        }
        if (remoteSuggestedDefault != null && providers.listProviderIds().contains(remoteSuggestedDefault)) {
            providers.setDefaultProviderId(remoteSuggestedDefault);
        }
    }

    private ListProvidersResponse fetchProvidersWithRetry(GrpcHsmClient client, String host, int port) {
        int maxAttempts = 5;
        RuntimeException lastError = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return client.listProviders();
            } catch (RuntimeException e) {
                lastError = e;
                log.warn("Waiting for hsm-signer gRPC {}:{} (attempt {}/{}): {}",
                        host, port, attempt, maxAttempts, e.getMessage());
                if (attempt < maxAttempts) {
                    try {
                        Thread.sleep(2000L);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException("Interrupted connecting to hsm-signer gRPC", ie);
                    }
                }
            }
        }
        throw new IllegalStateException("Unable to reach hsm-signer gRPC at " + host + ":" + port
                + " after " + maxAttempts + " attempts", lastError);
    }

    private void registerLocalDevices(PkcsProviders providers) {
        if (hsm.getLocalDevices() == null) {
            return;
        }
        for (HsmProperties.LocalDeviceProperties dev : hsm.getLocalDevices()) {
            if (!dev.isEnabled()) {
                continue;
            }
            if (dev.getId() == null || dev.getId().isBlank()) {
                throw new IllegalArgumentException("hsm.local-devices entries must specify a non-blank id");
            }
            Pkcs11OcspSigner signer = new Pkcs11OcspSigner(
                    dev.getPkcs11Library(),
                    dev.getTokenLabel(),
                    dev.getPin(),
                    dev.getKeyLabel(),
                    dev.getSlotIndex(),
                    dev.getConfigPath());
            providers.register(new SunPkcs11CryptoProviderAdapter(dev.getId().trim(), signer));
        }
    }

    @Bean
    @Profile("!prod")
    @ConditionalOnProperty(name = "hsm.enabled", havingValue = "false")
    public OcspSigner softwareSigner() {
        log.info("HSM disabled by configuration; using software signer.");
        return createFallbackSoftwareSigner();
    }

    private SoftwareKeyOcspSigner createFallbackSoftwareSigner() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            X500Name name = new X500Name("CN=Incert Delegated OCSP Signer (Fallback),O=Incert,C=CH");
            BigInteger serial = new BigInteger(63, new SecureRandom());
            Date notBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
            Date notAfter = Date.from(Instant.now().plus(30, ChronoUnit.DAYS));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.getPrivate());
            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name,
                SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded())
            );
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_OCSPSigning));

            X509CertificateHolder holder = builder.build(signer);
            return new SoftwareKeyOcspSigner(kp.getPrivate(), new X509CertificateHolder[]{holder}, notAfter.toInstant());
        } catch (Exception e) {
            throw new IllegalStateException("Could not create fallback signer", e);
        }
    }
}

