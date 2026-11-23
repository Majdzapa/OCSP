package com.company.incert.ocsp.signing.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * HSM / Cryptographic subsystem settings ({@code hsm.*}), bound from {@code application*.yml}.
 * <p>
 * Default {@code mode=DATABASE} loads cryptographic drivers ({@code crypto_providers}) and devices
 * ({@code crypto_devices}) from MariaDB with zero persisted PINs (Pattern 2 Runtime Activation) and
 * restricts native shared library loading to {@link #allowedLibraryDirs}.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "hsm")
public class HsmProperties {

    private boolean enabled = true;
    private String mode = "DATABASE";
    private String defaultProviderId;
    private String keyLabel = "ocsp-signing-key";

    private List<String> allowedLibraryDirs = new ArrayList<>(List.of(
            "/usr/lib/softhsm",
            "/usr/lib/x86_64-linux-gnu/softhsm",
            "/usr/lib/aarch64-linux-gnu/softhsm",
            "/opt/homebrew/lib/softhsm",
            "/opt/pkcs11j",
            "/opt/hsm",
            "/usr/safenet",
            "/opt/utimaco"
    ));
}
