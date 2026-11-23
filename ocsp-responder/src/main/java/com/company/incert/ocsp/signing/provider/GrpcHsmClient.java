package com.company.incert.ocsp.signing.provider;

import com.company.incert.hsm.grpc.v1.GenerateCsrRpcRequest;
import com.company.incert.hsm.grpc.v1.GenerateCsrRpcResponse;
import com.company.incert.hsm.grpc.v1.HealthRpcRequest;
import com.company.incert.hsm.grpc.v1.HealthRpcResponse;
import com.company.incert.hsm.grpc.v1.HsmSignerServiceGrpc;
import com.company.incert.hsm.grpc.v1.ImportCertificateRpcRequest;
import com.company.incert.hsm.grpc.v1.ImportCertificateRpcResponse;
import com.company.incert.hsm.grpc.v1.ListKeysRequest;
import com.company.incert.hsm.grpc.v1.ListKeysResponse;
import com.company.incert.hsm.grpc.v1.ListProvidersRequest;
import com.company.incert.hsm.grpc.v1.ListProvidersResponse;
import com.company.incert.hsm.grpc.v1.SignRpcRequest;
import com.google.protobuf.ByteString;
import io.grpc.ChannelCredentials;
import io.grpc.Grpc;
import io.grpc.InsecureChannelCredentials;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.TlsChannelCredentials;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.concurrent.TimeUnit;

/**
 * Thread-safe persistent gRPC client connected to one {@code hsm-signer} daemon
 * (supports plaintext for dev and mTLS via {@link TlsChannelCredentials} for production).
 */
public class GrpcHsmClient implements AutoCloseable {

    private final ManagedChannel channel;
    private final HsmSignerServiceGrpc.HsmSignerServiceBlockingStub stub;
    private final int timeoutSeconds;

    public GrpcHsmClient(
            String host,
            int port,
            int timeoutSeconds,
            boolean tlsEnabled,
            String keyStore,
            String keyStorePassword,
            String trustStore,
            String trustStorePassword,
            ResourceLoader resourceLoader) {
        try {
            ChannelCredentials creds = buildCredentials(
                    tlsEnabled, keyStore, keyStorePassword, trustStore, trustStorePassword, resourceLoader);
            this.channel = Grpc.newChannelBuilderForAddress(host, port, creds)
                    .keepAliveTime(30, TimeUnit.SECONDS)
                    .keepAliveTimeout(10, TimeUnit.SECONDS)
                    .keepAliveWithoutCalls(true)
                    .build();
            this.stub = HsmSignerServiceGrpc.newBlockingStub(this.channel);
            this.timeoutSeconds = Math.max(1, timeoutSeconds);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize gRPC client to HSM signer "
                    + host + ":" + port + ": " + e.getMessage(), e);
        }
    }

    public GrpcHsmClient(ManagedChannel channel, int timeoutSeconds) {
        this.channel = channel;
        this.stub = HsmSignerServiceGrpc.newBlockingStub(channel);
        this.timeoutSeconds = Math.max(1, timeoutSeconds);
    }

    public ListProvidersResponse listProviders() {
        try {
            return withDeadline().listProviders(ListProvidersRequest.getDefaultInstance());
        } catch (StatusRuntimeException e) {
            throw translateGrpcException(e);
        }
    }

    public ListKeysResponse listKeys(String providerId) {
        try {
            return withDeadline().listKeys(ListKeysRequest.newBuilder().setProviderId(providerId).build());
        } catch (StatusRuntimeException e) {
            throw translateGrpcException(e);
        }
    }

    public GenerateCsrRpcResponse generateCsr(
            String providerId,
            String keyLabel,
            String subjectDn,
            String keyAlgorithm,
            int keySize,
            boolean reuseExistingKey) {
        try {
            return withDeadline().generateCsr(GenerateCsrRpcRequest.newBuilder()
                    .setProviderId(providerId)
                    .setKeyLabel(keyLabel)
                    .setSubjectDn(subjectDn)
                    .setKeyAlgorithm(keyAlgorithm != null ? keyAlgorithm : "RSA")
                    .setKeySize(keySize)
                    .setReuseExistingKey(reuseExistingKey)
                    .build());
        } catch (StatusRuntimeException e) {
            throw translateGrpcException(e);
        }
    }

    public ImportCertificateRpcResponse importCertificate(String providerId, String keyLabel, byte[] certDer) {
        try {
            return withDeadline().importCertificate(ImportCertificateRpcRequest.newBuilder()
                    .setProviderId(providerId)
                    .setKeyLabel(keyLabel)
                    .setCertificateDer(ByteString.copyFrom(certDer))
                    .build());
        } catch (StatusRuntimeException e) {
            throw translateGrpcException(e);
        }
    }

    public byte[] sign(String providerId, String keyLabel, String signatureAlgorithm, byte[] data) {
        try {
            return withDeadline().sign(SignRpcRequest.newBuilder()
                    .setProviderId(providerId)
                    .setKeyLabel(keyLabel)
                    .setSignatureAlgorithm(signatureAlgorithm)
                    .setData(ByteString.copyFrom(data))
                    .build())
                    .getSignature()
                    .toByteArray();
        } catch (StatusRuntimeException e) {
            throw translateGrpcException(e);
        }
    }

    public HealthRpcResponse health() {
        try {
            return withDeadline().health(HealthRpcRequest.getDefaultInstance());
        } catch (StatusRuntimeException e) {
            throw translateGrpcException(e);
        }
    }

    @Override
    public void close() {
        channel.shutdown();
        try {
            if (!channel.awaitTermination(5, TimeUnit.SECONDS)) {
                channel.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            channel.shutdownNow();
        }
    }

    private HsmSignerServiceGrpc.HsmSignerServiceBlockingStub withDeadline() {
        return stub.withDeadlineAfter(timeoutSeconds, TimeUnit.SECONDS);
    }

    private static RuntimeException translateGrpcException(StatusRuntimeException e) {
        Status.Code code = e.getStatus().getCode();
        String desc = e.getStatus().getDescription();
        String msg = (desc != null && !desc.isBlank()) ? desc : e.getStatus().toString();
        if (code == Status.Code.INVALID_ARGUMENT) {
            return new IllegalArgumentException(msg, e);
        }
        if (code == Status.Code.FAILED_PRECONDITION) {
            return new IllegalStateException(msg, e);
        }
        return new IllegalStateException("HSM gRPC call failed [" + code + "]: " + msg, e);
    }

    private static ChannelCredentials buildCredentials(
            boolean tlsEnabled,
            String keyStore,
            String keyStorePassword,
            String trustStore,
            String trustStorePassword,
            ResourceLoader resourceLoader) throws Exception {
        if (!tlsEnabled) {
            return InsecureChannelCredentials.create();
        }
        TlsChannelCredentials.Builder builder = TlsChannelCredentials.newBuilder();
        if (keyStore != null && !keyStore.isBlank()) {
            KeyStore ks = loadKeyStore(keyStore, keyStorePassword, resourceLoader);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, keyStorePassword != null ? keyStorePassword.toCharArray() : new char[0]);
            builder.keyManager(kmf.getKeyManagers());
        }
        if (trustStore != null && !trustStore.isBlank()) {
            KeyStore ts = loadKeyStore(trustStore, trustStorePassword, resourceLoader);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            builder.trustManager(tmf.getTrustManagers());
        }
        return builder.build();
    }

    private static KeyStore loadKeyStore(String location, String password, ResourceLoader resourceLoader) throws Exception {
        String resolved = (location.startsWith("classpath:") || location.startsWith("file:"))
                ? location
                : "file:" + location;
        Resource resource = resourceLoader.getResource(resolved);
        if (!resource.exists()) {
            throw new IOException("HSM gRPC keystore/truststore not found: " + location);
        }
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = resource.getInputStream()) {
            ks.load(in, password != null ? password.toCharArray() : new char[0]);
        }
        return ks;
    }
}

