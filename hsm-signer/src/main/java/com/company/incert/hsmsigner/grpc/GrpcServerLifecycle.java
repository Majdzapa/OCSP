package com.company.incert.hsmsigner.grpc;

import com.company.incert.hsmsigner.config.HsmSignerProperties;
import io.grpc.Grpc;
import io.grpc.InsecureServerCredentials;
import io.grpc.Server;
import io.grpc.ServerCredentials;
import io.grpc.TlsServerCredentials;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.SmartLifecycle;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;

/**
 * Manages the Netty-shaded gRPC server lifecycle (plaintext or mTLS).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class GrpcServerLifecycle implements SmartLifecycle {

    private final HsmSignerProperties properties;
    private final HsmSignerGrpcService grpcService;
    private final ResourceLoader resourceLoader;

    private volatile Server server;
    private volatile boolean running;

    @Override
    public synchronized void start() {
        if (running) {
            return;
        }
        int port = properties.getGrpc().getPort();
        try {
            ServerCredentials creds = buildCredentials(properties.getGrpc().getTls());
            server = Grpc.newServerBuilderForPort(port, creds)
                    .addService(grpcService)
                    .permitKeepAliveWithoutCalls(true)
                    .permitKeepAliveTime(30, TimeUnit.SECONDS)
                    .build()
                    .start();
            running = true;
            log.info("HSM Signer gRPC server started on port {} (tls={})",
                    port, properties.getGrpc().getTls().isEnabled());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to start HSM Signer gRPC server on port " + port, e);
        }
    }

    @Override
    public synchronized void stop() {
        running = false;
        if (server != null) {
            server.shutdown();
            try {
                if (!server.awaitTermination(5, TimeUnit.SECONDS)) {
                    server.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                server.shutdownNow();
            }
            server = null;
            log.info("HSM Signer gRPC server stopped");
        }
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    private ServerCredentials buildCredentials(HsmSignerProperties.TlsConfig tls) throws Exception {
        if (tls == null || !tls.isEnabled()) {
            return InsecureServerCredentials.create();
        }
        KeyStore ks = loadKeyStore(tls.getKeyStore(), tls.getKeyStorePassword(), tls.getKeyStoreType());
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, tls.getKeyStorePassword() != null ? tls.getKeyStorePassword().toCharArray() : new char[0]);

        TlsServerCredentials.Builder builder = TlsServerCredentials.newBuilder()
                .keyManager(kmf.getKeyManagers());

        if (tls.getTrustStore() != null && !tls.getTrustStore().isBlank()) {
            KeyStore ts = loadKeyStore(tls.getTrustStore(), tls.getTrustStorePassword(), tls.getTrustStoreType());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            builder.trustManager(tmf.getTrustManagers());
            builder.clientAuth(tls.isClientAuth()
                    ? TlsServerCredentials.ClientAuth.REQUIRE
                    : TlsServerCredentials.ClientAuth.OPTIONAL);
        }
        return builder.build();
    }

    private KeyStore loadKeyStore(String location, String password, String type) throws Exception {
        if (location == null || location.isBlank()) {
            throw new IllegalArgumentException("gRPC TLS keystore/truststore location must be configured when TLS is enabled");
        }
        String resolved = (location.startsWith("classpath:") || location.startsWith("file:"))
                ? location
                : "file:" + location;
        Resource resource = resourceLoader.getResource(resolved);
        if (!resource.exists()) {
            throw new IOException("TLS keystore/truststore not found: " + location);
        }
        KeyStore ks = KeyStore.getInstance(type != null && !type.isBlank() ? type : "PKCS12");
        try (InputStream in = resource.getInputStream()) {
            ks.load(in, password != null ? password.toCharArray() : new char[0]);
        }
        return ks;
    }
}

