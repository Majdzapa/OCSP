package com.company.incert.ocsp.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** PKCS#11 / SoftHSM2 settings ({@code hsm.*}), bound from {@code application*.yml}. */
@Getter
@Setter
@ConfigurationProperties(prefix = "hsm")
public class HsmProperties {

    private boolean enabled;
    private String pkcs11Library;
    private String tokenLabel;
    private int slotIndex;
    private String pin;
    private String keyLabel;
    private String configPath;
}
