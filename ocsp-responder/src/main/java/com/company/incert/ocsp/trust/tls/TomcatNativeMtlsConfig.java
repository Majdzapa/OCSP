package com.company.incert.ocsp.trust.tls;

import com.company.incert.ocsp.shared.config.AppSecurityProperties;
import com.company.incert.ocsp.trust.service.TrustedCaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Native Tomcat HTTPS mTLS connector with zero-restart truststore hot-reload.
 * <p>
 * Activated when {@code security.tls.client-cert-auth-enabled=true} and {@code security.tls.key-store}
 * is configured. Uses {@code certificateVerification="optional"} (TLS {@code WANT}) so browsers display
 * their native certificate picker filtered by the active Trusted CAs in {@link TrustedCaService},
 * while still allowing fallback to Username/Password or Keycloak when no certificate is chosen.
 * <p>
 * Whenever a Trusted CA is imported, toggled, or deleted, {@link #onTrustedCasReloaded} updates
 * Tomcat's in-memory trust {@link KeyStore} and calls {@code protocol.reloadSslHostConfigs()}
 * so changes take effect immediately without restarting the application.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class TomcatNativeMtlsConfig {

    private final AppSecurityProperties securityProperties;
    private final TrustedCaService trustedCaService;
    private final ResourceLoader resourceLoader;

    private final AtomicReference<Http11NioProtocol> mtlsProtocolRef = new AtomicReference<>();
    private final AtomicReference<SSLHostConfig> sslHostConfigRef = new AtomicReference<>();

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> nativeMtlsConnectorCustomizer() {
        return factory -> {
            AppSecurityProperties.Tls tls = securityProperties.getTls();
            if (!tls.isClientCertAuthEnabled() || tls.getKeyStore() == null || tls.getKeyStore().isBlank()) {
                log.info("Native Tomcat mTLS HTTPS connector not active (clientCertAuthEnabled={}, keyStoreConfigured={})",
                        tls.isClientCertAuthEnabled(), tls.getKeyStore() != null && !tls.getKeyStore().isBlank());
                return;
            }
            try {
                Connector connector = buildMtlsConnector(tls);
                factory.addAdditionalConnectors(connector);
                log.info("Started native Tomcat mTLS HTTPS connector on port {} (certificateVerification=optional, zero-restart hot-reload enabled)",
                        tls.getHttpsPort());
            } catch (Exception e) {
                throw new IllegalStateException("Failed to configure native Tomcat mTLS HTTPS connector: " + e.getMessage(), e);
            }
        };
    }

    @EventListener(TrustedCasReloadedEvent.class)
    public void onTrustedCasReloaded(TrustedCasReloadedEvent event) {
        Http11NioProtocol protocol = mtlsProtocolRef.get();
        SSLHostConfig hostConfig = sslHostConfigRef.get();
        if (protocol != null && hostConfig != null) {
            try {
                hostConfig.setTrustStore(buildTrustKeyStore(trustedCaService.getActiveTrustedCas()));
                protocol.reloadSslHostConfigs();
                log.info("Hot-reloaded native Tomcat mTLS truststore in memory (activeCAs={}, zero restart)", event.activeCount());
            } catch (Exception e) {
                log.warn("Failed to hot-reload Tomcat SSLHostConfigs: {}", e.getMessage());
            }
        }
    }

    private Connector buildMtlsConnector(AppSecurityProperties.Tls tls) throws Exception {
        String passwordStr = tls.getKeyStorePassword() != null ? tls.getKeyStorePassword() : "";
        char[] password = passwordStr.toCharArray();
        String storeType = tls.getKeyStoreType() != null && !tls.getKeyStoreType().isBlank() ? tls.getKeyStoreType() : "PKCS12";

        KeyStore keyStore = KeyStore.getInstance(storeType);
        Resource ksResource = resourceLoader.getResource(tls.getKeyStore());
        try (InputStream is = ksResource.getInputStream()) {
            keyStore.load(is, password);
        }

        Connector connector = new Connector(Http11NioProtocol.class.getName());
        connector.setScheme("https");
        connector.setSecure(true);
        connector.setPort(tls.getHttpsPort());

        Http11NioProtocol protocol = (Http11NioProtocol) connector.getProtocolHandler();
        protocol.setSSLEnabled(true);

        SSLHostConfig sslHostConfig = new SSLHostConfig();
        sslHostConfig.setHostName("_default_");
        sslHostConfig.setCertificateVerification("optional");
        sslHostConfig.setProtocols("TLSv1.2+TLSv1.3");
        sslHostConfig.setTrustStore(buildTrustKeyStore(trustedCaService.getActiveTrustedCas()));

        SSLHostConfigCertificate cert = new SSLHostConfigCertificate(sslHostConfig, SSLHostConfigCertificate.Type.UNDEFINED);
        cert.setCertificateKeystore(keyStore);
        cert.setCertificateKeystorePassword(passwordStr);
        sslHostConfig.addCertificate(cert);

        protocol.addSslHostConfig(sslHostConfig);
        mtlsProtocolRef.set(protocol);
        sslHostConfigRef.set(sslHostConfig);
        return connector;
    }

    public static KeyStore buildTrustKeyStore(List<X509Certificate> cas) throws Exception {
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        for (int i = 0; i < cas.size(); i++) {
            trustStore.setCertificateEntry("trusted-ca-" + i, cas.get(i));
        }
        return trustStore;
    }
}
