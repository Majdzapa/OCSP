package com.company.incert.ocsp.signing.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * HSM / Cryptographic provider settings ({@code hsm.*}), bound from {@code application*.yml}.
 * Supports remote PKCS11J over gRPC ({@code mode=GRPC}), local SunPKCS11 tokens ({@code mode=SUN_PKCS11}),
 * and multiple concurrent signing devices registered in {@code PkcsProviders}.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "hsm")
public class HsmProperties {

    private boolean enabled;
    private String mode = "SUN_PKCS11";
    private String defaultProviderId;
    private String pkcs11Library;
    private String tokenLabel;
    private int slotIndex;
    private String pin;
    private String keyLabel;
    private String configPath;

    private GrpcClientProperties grpc = new GrpcClientProperties();
    private List<LocalDeviceProperties> localDevices = new ArrayList<>();

    @Getter
    @Setter
    public static class GrpcClientProperties {
        private String idPrefix;
        private String host = "localhost";
        private int port = 9090;
        private int timeoutSeconds = 10;
        private boolean tlsEnabled = false;
        private String keyStore;
        private String keyStorePassword;
        private String trustStore;
        private String trustStorePassword;
        private List<GrpcClientProperties> endpoints = new ArrayList<>();
    }

    @Getter
    @Setter
    public static class LocalDeviceProperties {
        private String id;
        private boolean enabled = true;
        private String pkcs11Library;
        private String tokenLabel;
        private int slotIndex = 0;
        private String pin;
        private String keyLabel;
        private String configPath;
    }
}
