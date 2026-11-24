package com.company.incert.ocsp.signing.provider;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Security guard enforcing that DB-configured PKCS#11 drivers and JNI wrapper binaries
 * can only be loaded from explicitly allowlisted host directories (mitigating arbitrary {@code dlopen} RCE).
 */
public final class LibraryPathAllowlist {

    private final List<Path> allowedDirs;

    public LibraryPathAllowlist(List<String> directories) {
        if (directories == null || directories.isEmpty()) {
            this.allowedDirs = List.of();
        } else {
            this.allowedDirs = directories.stream()
                    .filter(Objects::nonNull)
                    .map(String::trim)
                    .filter(s -> !s.isBlank())
                    .map(s -> Path.of(s).toAbsolutePath().normalize())
                    .distinct()
                    .toList();
        }
    }

    public String validateLibraryPath(String libraryPath) {
        if (libraryPath == null || libraryPath.isBlank()) {
            throw new IllegalArgumentException("libraryPath must not be blank");
        }
        return validateNormalizedAbsoluteFile(libraryPath, "libraryPath");
    }

    public static final String DEFAULT_WRAPPER_PATH = "/opt/pkcs11j/libpkcs11wrapper.so";

    public String validateWrapperPath(String wrapperPath) {
        if (wrapperPath == null || wrapperPath.isBlank()) {
            return validateNormalizedAbsoluteFile(DEFAULT_WRAPPER_PATH, "libraryWrapperPath");
        }
        String trimmed = wrapperPath.trim();
        if ("embedded".equalsIgnoreCase(trimmed) || "auto".equalsIgnoreCase(trimmed)) {
            return validateNormalizedAbsoluteFile(DEFAULT_WRAPPER_PATH, "libraryWrapperPath");
        }
        return validateNormalizedAbsoluteFile(trimmed, "libraryWrapperPath");
    }

    public List<String> getAllowedDirectories() {
        return allowedDirs.stream().map(Path::toString).toList();
    }

    private String validateNormalizedAbsoluteFile(String rawPath, String fieldName) {
        String trimmed = rawPath.trim();
        Path raw = Path.of(trimmed);
        if (!raw.isAbsolute()) {
            throw new IllegalArgumentException(fieldName + " must be an absolute path: '" + trimmed + "'");
        }
        if (trimmed.contains("..")) {
            throw new IllegalArgumentException(fieldName + " must not contain path traversal segments: '" + trimmed + "'");
        }
        if (allowedDirs.isEmpty()) {
            throw new IllegalStateException("No hsm.allowed-library-dirs configured; refusing to load native library");
        }
        Path normalized = raw.toAbsolutePath().normalize();
        boolean permitted = allowedDirs.stream().anyMatch(dir -> normalized.startsWith(dir) && !normalized.equals(dir));
        if (!permitted) {
            throw new IllegalArgumentException(fieldName + " '" + normalized
                    + "' is outside hsm.allowed-library-dirs " + getAllowedDirectories());
        }
        return normalized.toString();
    }
}

