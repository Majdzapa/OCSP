package com.company.incert.hsmsigner.grpc;

import com.company.incert.hsm.grpc.v1.GenerateCsrRpcRequest;
import com.company.incert.hsm.grpc.v1.GenerateCsrRpcResponse;
import com.company.incert.hsm.grpc.v1.HealthRpcRequest;
import com.company.incert.hsm.grpc.v1.HealthRpcResponse;
import com.company.incert.hsm.grpc.v1.HsmSignerServiceGrpc;
import com.company.incert.hsm.grpc.v1.ImportCertificateRpcRequest;
import com.company.incert.hsm.grpc.v1.ImportCertificateRpcResponse;
import com.company.incert.hsm.grpc.v1.KeyDescriptor;
import com.company.incert.hsm.grpc.v1.ListKeysRequest;
import com.company.incert.hsm.grpc.v1.ListKeysResponse;
import com.company.incert.hsm.grpc.v1.ListProvidersRequest;
import com.company.incert.hsm.grpc.v1.ListProvidersResponse;
import com.company.incert.hsm.grpc.v1.ProviderDescriptor;
import com.company.incert.hsm.grpc.v1.SignRpcRequest;
import com.company.incert.hsm.grpc.v1.SignRpcResponse;
import com.company.incert.pkcs11j.KeyMetadata;
import com.company.incert.pkcs11j.Pkcs11Exception;
import com.company.incert.pkcs11j.provider.Pkcs11Provider;
import com.company.incert.pkcs11j.provider.PkcsProviders;
import com.google.protobuf.ByteString;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * gRPC facade exposing all registered PKCS11J providers in {@link PkcsProviders} as stateless RPCs.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class HsmSignerGrpcService extends HsmSignerServiceGrpc.HsmSignerServiceImplBase {

    @FunctionalInterface
    private interface RpcAction<T> {
        T run() throws Exception;
    }

    private final PkcsProviders pkcsProviders;

    @Override
    public void listProviders(ListProvidersRequest request, StreamObserver<ListProvidersResponse> observer) {
        executeUnary(observer, () -> {
            ListProvidersResponse.Builder builder = ListProvidersResponse.newBuilder()
                    .addAllProviders(buildProviderDescriptors());
            if (pkcsProviders.getDefaultProviderId() != null) {
                builder.setDefaultProviderId(pkcsProviders.getDefaultProviderId());
            }
            return builder.build();
        });
    }

    @Override
    public void listKeys(ListKeysRequest request, StreamObserver<ListKeysResponse> observer) {
        executeUnary(observer, () -> {
            Pkcs11Provider provider = pkcsProviders.getProvider(request.getProviderId());
            List<KeyDescriptor> keys = provider.listKeys().stream()
                    .map(HsmSignerGrpcService::toKeyDescriptor)
                    .toList();
            return ListKeysResponse.newBuilder()
                    .setProviderId(provider.getProviderId())
                    .addAllKeys(keys)
                    .build();
        });
    }

    @Override
    public void generateCsr(GenerateCsrRpcRequest request, StreamObserver<GenerateCsrRpcResponse> observer) {
        executeUnary(observer, () -> {
            Pkcs11Provider provider = pkcsProviders.getProvider(request.getProviderId());
            String csrPem = provider.generateCsr(
                    request.getKeyLabel(),
                    request.getSubjectDn(),
                    request.getKeyAlgorithm(),
                    request.getKeySize(),
                    request.getReuseExistingKey());
            String keyAlg = (request.getKeyAlgorithm() != null && !request.getKeyAlgorithm().isBlank())
                    ? request.getKeyAlgorithm()
                    : "RSA";
            return GenerateCsrRpcResponse.newBuilder()
                    .setProviderId(provider.getProviderId())
                    .setKeyLabel(request.getKeyLabel().trim())
                    .setSubjectDn(request.getSubjectDn().trim())
                    .setKeyAlgorithm(keyAlg)
                    .setCsrPem(csrPem)
                    .build();
        });
    }

    @Override
    public void importCertificate(
            ImportCertificateRpcRequest request,
            StreamObserver<ImportCertificateRpcResponse> observer) {
        executeUnary(observer, () -> {
            Pkcs11Provider provider = pkcsProviders.getProvider(request.getProviderId());
            X509CertificateHolder holder = new X509CertificateHolder(request.getCertificateDer().toByteArray());
            provider.importCertificate(request.getKeyLabel(), holder);
            return ImportCertificateRpcResponse.newBuilder()
                    .setImported(true)
                    .setMessage("Imported certificate under keyLabel='" + request.getKeyLabel()
                            + "' on provider '" + provider.getProviderId() + "'")
                    .build();
        });
    }

    @Override
    public void sign(SignRpcRequest request, StreamObserver<SignRpcResponse> observer) {
        executeUnary(observer, () -> {
            Pkcs11Provider provider = pkcsProviders.getProvider(request.getProviderId());
            byte[] signature = provider.sign(
                    request.getKeyLabel(),
                    request.getSignatureAlgorithm(),
                    request.getData().toByteArray());
            return SignRpcResponse.newBuilder()
                    .setSignature(ByteString.copyFrom(signature))
                    .build();
        });
    }

    @Override
    public void health(HealthRpcRequest request, StreamObserver<HealthRpcResponse> observer) {
        executeUnary(observer, () -> {
            List<ProviderDescriptor> descriptors = buildProviderDescriptors();
            boolean allHealthy = !descriptors.isEmpty() && descriptors.stream().allMatch(ProviderDescriptor::getHealthy);
            return HealthRpcResponse.newBuilder()
                    .setHealthy(allHealthy)
                    .addAllProviders(descriptors)
                    .build();
        });
    }

    private <T> void executeUnary(StreamObserver<T> observer, RpcAction<T> action) {
        try {
            observer.onNext(action.run());
            observer.onCompleted();
        } catch (Exception e) {
            observer.onError(toGrpcError(e));
        }
    }

    private List<ProviderDescriptor> buildProviderDescriptors() {
        return pkcsProviders.listProviders().stream()
                .map(this::toDescriptor)
                .toList();
    }

    private ProviderDescriptor toDescriptor(Pkcs11Provider provider) {
        boolean healthy;
        String statusMsg;
        List<KeyDescriptor> keys = List.of();
        try {
            statusMsg = provider.healthCheck();
            keys = provider.listKeys().stream()
                    .map(HsmSignerGrpcService::toKeyDescriptor)
                    .toList();
            healthy = true;
        } catch (Exception e) {
            healthy = false;
            statusMsg = "DOWN: " + e.getMessage();
        }
        return ProviderDescriptor.newBuilder()
                .setProviderId(provider.getProviderId())
                .setProviderType("PKCS11J")
                .setLibraryPath(provider.getLibraryPath())
                .setTokenLabel(provider.getTokenLabel())
                .setSlotId(provider.getSlotId())
                .setHealthy(healthy)
                .setStatusMessage(statusMsg)
                .addAllKeys(keys)
                .build();
    }

    private static KeyDescriptor toKeyDescriptor(KeyMetadata k) {
        return KeyDescriptor.newBuilder()
                .setKeyLabel(k.keyLabel())
                .setKeyAlgorithm(k.keyAlgorithm())
                .setKeySize(k.keySizeBits())
                .build();
    }

    private static Throwable toGrpcError(Exception e) {
        if (e instanceof IllegalArgumentException) {
            return Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException();
        }
        if (e instanceof IllegalStateException) {
            return Status.FAILED_PRECONDITION.withDescription(e.getMessage()).asRuntimeException();
        }
        if (e instanceof Pkcs11Exception pkcsEx) {
            log.error("PKCS#11 error during gRPC call: {}", pkcsEx.getMessage());
            return Status.INTERNAL.withDescription(pkcsEx.getMessage()).asRuntimeException();
        }
        log.error("Unexpected error in HSM gRPC service: {}", e.getMessage(), e);
        return Status.INTERNAL.withDescription(e.getMessage()).asRuntimeException();
    }
}
