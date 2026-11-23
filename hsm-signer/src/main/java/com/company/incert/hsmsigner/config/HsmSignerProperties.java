package com.company.incert.hsmsigner.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties ({@code hsm-signer.*}) defining the gRPC endpoint and
 * one or more PKCS#11 devices managed simultaneously by {@code PkcsProviders}.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "hsm-signer")
public class HsmSignerProperties {

    private GrpcConfig grpc = new GrpcConfig();
    private String defaultProviderId;
    private List<ProviderEntry> providers = new ArrayList<>();

    @Getter
    @Setter
    public static class GrpcConfig {
        private int port = 9090;
        private TlsConfig tls = new TlsConfig();
    }

    @Getter
    @Setter
    public static class TlsConfig {
        private boolean enabled = false;
        private String keyStore;
        private String keyStorePassword;
        private String keyStoreType = "PKCS12";
        private String trustStore;
        private String trustStorePassword;
        private String trustStoreType = "PKCS12";
        private boolean clientAuth = true;
    }

    @Getter
    @Setter
    public static class ProviderEntry {
        private String id;
        private boolean enabled = true;
        private String libraryPath;
        private String tokenLabel;
        private Long slotId;
        private int slotListIndex = 0;
        private String pin;
        private int poolSize = 4;
        private boolean prehashInJvm = false;
    }
}

