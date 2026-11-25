package lu.incert.ocsp.signing;

import lu.incert.ocsp.signing.provider.LibraryPathAllowlist;
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
        assertThat(allowlist.validateWrapperPath("/opt/pkcs11j/libpkcs11wrapper.so"))
                .isEqualTo("/opt/pkcs11j/libpkcs11wrapper.so");
        assertThat(allowlist.validateWrapperPath(null)).isNull();
        assertThat(allowlist.validateWrapperPath("  ")).isNull();
        assertThat(allowlist.validateWrapperPath("embedded")).isNull();
        assertThat(allowlist.validateWrapperPath("auto")).isNull();
        assertThat(allowlist.validateWrapperPath("/opt/pkcs11j/libpkcs11j.so"))
                .isEqualTo("/opt/pkcs11j/libpkcs11j.so");

        LibraryPathAllowlist withConfiguredDefault = new LibraryPathAllowlist(
                List.of("/usr/lib/softhsm", "/opt/pkcs11j"),
                "/opt/pkcs11j/libpkcs11wrapper.so"
        );
        assertThat(withConfiguredDefault.validateWrapperPath(null))
                .isEqualTo("/opt/pkcs11j/libpkcs11wrapper.so");
        assertThat(withConfiguredDefault.validateWrapperPath("auto"))
                .isEqualTo("/opt/pkcs11j/libpkcs11wrapper.so");
    }

    @Test
    void rejectsTraversalRelativeAndUnlistedLibraryPaths() {
        assertThatThrownBy(() -> allowlist.validateLibraryPath("/usr/lib/softhsm/../evil.so"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("traversal");
        assertThatThrownBy(() -> allowlist.validateLibraryPath("libsofthsm2.so"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be an absolute path");
        assertThatThrownBy(() -> allowlist.validateLibraryPath("/usr/lib/softhsm"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside hsm.allowed-library-dirs");
        assertThatThrownBy(() -> allowlist.validateLibraryPath("/usr/lib/softhsm-evil/lib.so"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside hsm.allowed-library-dirs");
        assertThatThrownBy(() -> allowlist.validateLibraryPath("/usr/lib/softhsm\\evil.so"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> allowlist.validateLibraryPath("/tmp/arbitrary.so"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside hsm.allowed-library-dirs");
        assertThatThrownBy(() -> allowlist.validateWrapperPath("/tmp/evil_wrapper.so"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside hsm.allowed-library-dirs");
    }

    @Test
    void validatesWindowsDrivePathsConsistentlyAcrossOperatingSystems() {
        LibraryPathAllowlist winAllowlist = new LibraryPathAllowlist(List.of(
                "C:\\SoftHSM2\\lib",
                "D:/opt/pkcs11j"
        ));

        assertThat(winAllowlist.validateLibraryPath("C:\\SoftHSM2\\lib\\softhsm2-x64.dll"))
                .isEqualTo("C:\\SoftHSM2\\lib\\softhsm2-x64.dll");
        assertThat(winAllowlist.validateLibraryPath("c:/softhsm2/lib/softhsm2-x64.dll"))
                .isEqualTo("C:\\softhsm2\\lib\\softhsm2-x64.dll");
        assertThat(winAllowlist.validateWrapperPath("D:\\opt\\pkcs11j\\pkcs11wrapper.dll"))
                .isEqualTo("D:\\opt\\pkcs11j\\pkcs11wrapper.dll");

        assertThatThrownBy(() -> winAllowlist.validateLibraryPath("C:\\SoftHSM2\\lib\\..\\evil.dll"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("traversal");
        assertThatThrownBy(() -> winAllowlist.validateLibraryPath("C:relative.dll"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be an absolute path");
        assertThatThrownBy(() -> winAllowlist.validateLibraryPath("\\\\attacker\\share\\evil.dll"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("UNC");
        assertThatThrownBy(() -> winAllowlist.validateLibraryPath("C:\\Windows\\System32\\evil.dll"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside hsm.allowed-library-dirs");
    }
}

