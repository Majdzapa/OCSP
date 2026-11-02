package com.company.ocsp.responder.config;

import com.company.ocsp.responder.service.KmsHttpClient;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactoryBuilder;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.security.KeyStore;

/**
 * Builds the {@link KmsHttpClient} bean for the OCSP responder.
 *
 * <h2>mTLS toggle</h2>
 * <ul>
 *   <li>{@code kms.mtls.enabled=false} (default) — plain HTTP, no client cert.
 *       Use this for local development with the mock KMS.</li>
 *   <li>{@code kms.mtls.enabled=true} — loads the PKCS12 keystore and truststore
 *       and enforces mutual TLS. Required in production.</li>
 * </ul>
 */
@Slf4j
@Configuration
public class KmsClientConfig {

    @Value("${kms.base-url}")
    private String baseUrl;

    @Value("${kms.mtls.enabled:false}")
    private boolean mtlsEnabled;

    @Value("${kms.truststore.path:none}")
    private String truststorePath;
    @Value("${kms.truststore.password:changeme}")
    private String truststorePassword;
    @Value("${kms.keystore.path:none}")
    private String keystorePath;
    @Value("${kms.keystore.password:changeme}")
    private String keystorePassword;

    @Bean
    public KmsHttpClient kmsHttpClient() throws Exception {
        log.info("Initialising KMS HTTP client (responder). base-url={} mtls={}", baseUrl, mtlsEnabled);

        CloseableHttpClient httpClient;
        if (mtlsEnabled) {
            log.info("  mTLS enabled. truststore={} keystore={}", truststorePath, keystorePath);
            SSLContext sslContext = SSLContextBuilder.create()
                    .loadTrustMaterial(loadKeyStore(truststorePath, truststorePassword), null)
                    .loadKeyMaterial(loadKeyStore(keystorePath, keystorePassword),
                                     keystorePassword.toCharArray())
                    .build();

            httpClient = HttpClients.custom()
                    .setConnectionManager(
                        PoolingHttpClientConnectionManagerBuilder.create()
                            .setSSLSocketFactory(
                                SSLConnectionSocketFactoryBuilder.create()
                                    .setSslContext(sslContext)
                                    .setTlsVersions(
                                        org.apache.hc.core5.http.ssl.TLS.V_1_3,
                                        org.apache.hc.core5.http.ssl.TLS.V_1_2)
                                    .build()
                            )
                            .setMaxConnTotal(100)
                            .setMaxConnPerRoute(50)
                            .build()
                    )
                    .build();
        } else {
            log.warn("  mTLS disabled — using plain HTTP. Set kms.mtls.enabled=true in production.");
            httpClient = HttpClients.custom()
                    .setConnectionManager(
                        PoolingHttpClientConnectionManagerBuilder.create()
                            .setMaxConnTotal(100)
                            .setMaxConnPerRoute(50)
                            .build()
                    )
                    .build();
        }

        RestClient restClient = RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(new HttpComponentsClientHttpRequestFactory(httpClient))
                .build();

        return HttpServiceProxyFactory
                .builderFor(RestClientAdapter.create(restClient))
                .build()
                .createClient(KmsHttpClient.class);
    }

    private KeyStore loadKeyStore(String path, String password) throws Exception {
        String cleanPath = path.startsWith("file:") ? path.substring(5) : path;
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(Path.of(cleanPath).toFile())) {
            ks.load(fis, password.toCharArray());
        }
        return ks;
    }
}
