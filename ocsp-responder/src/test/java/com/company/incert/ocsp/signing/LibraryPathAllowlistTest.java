package com.company.incert.ocsp.signing;

import com.company.incert.ocsp.signing.provider.LibraryPathAllowlist;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LibraryPathAllowlistTest {

    private final LibraryPathAllowlist allowlist = new LibraryPathAllowlist(List.of(
            "/usr/lib/softhsm",
            "/opt/pkcs11j"
    ));

    @Test
    void acceptsLibrariesAndWrappersInsideAllowlistedDirectories() {
        assertThat(allowlist.validateLibraryPath("/usr/lib/softhsm/libsofthsm2.so"))
                .isEqualTo("/usr/lib/softhsm/libsofthsm2.so");
        assertThat(allowlist.validateWrapperPath("embedded")).isEqualTo("embedded");
        assertThat(allowlist.validateWrapperPath("auto")).isEqualTo("embedded");
        assertThat(allowlist.validateWrapperPath(null)).isEqualTo("embedded");
        assertThat(allowlist.validateWrapperPath("/opt/pkcs11j/libpkcs11j.so"))
                .isEqualTo("/opt/pkcs11j/libpkcs11j.so");
    }

    @Test
    void rejectsTraversalRelativeAndUnlistedLibraryPaths() {
        assertThatThrownBy(() -> allowlist.validateLibraryPath("/usr/lib/softhsm/../evil.so"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> allowlist.validateLibraryPath("libsofthsm2.so"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> allowlist.validateLibraryPath("/tmp/arbitrary.so"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside hsm.allowed-library-dirs");
        assertThatThrownBy(() -> allowlist.validateWrapperPath("/tmp/evil_wrapper.so"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside hsm.allowed-library-dirs");
    }
}

