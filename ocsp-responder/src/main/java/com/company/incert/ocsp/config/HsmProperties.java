package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** PKCS#11 / SoftHSM2 settings ({@code hsm.*}). */
@Getter
@Setter
@ConfigurationProperties(prefix = "hsm")
public class HsmProperties {

    private boolean enabled = true;
    private String pkcs11Library = "";
    private String tokenLabel = "ocsp-signing";
    private int slotIndex = 0;
    private String pin = "1234";
    private String keyLabel = "ocsp-signing-key";
    private String configPath = "";
}

