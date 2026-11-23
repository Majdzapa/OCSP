package com.company.incert.pkcs11j.nativebridge;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Loads the platform-specific native JNI shared library ({@code libpkcs11j.so} or {@code libpkcs11j.dylib})
 * once per JVM process, checking {@code -Dpkcs11j.native.lib} first and otherwise extracting from classpath.
 */
public final class NativeLibraryLoader {

    private static final AtomicBoolean LOADED = new AtomicBoolean(false);

    private NativeLibraryLoader() {}

    public static void ensureLoaded() {
        if (LOADED.get()) {
            return;
        }
        synchronized (NativeLibraryLoader.class) {
            if (LOADED.get()) {
                return;
            }
            String overridePath = System.getProperty("pkcs11j.native.lib");
            if (overridePath != null && !overridePath.isBlank()) {
                System.load(Path.of(overridePath.trim()).toAbsolutePath().toString());
                LOADED.set(true);
                return;
            }

            String os = detectOs();
            String arch = detectArch();
            String ext = "osx".equals(os) ? "dylib" : "so";
            String resourcePath = "/native/" + os + "-" + arch + "/libpkcs11j." + ext;

            try (InputStream in = NativeLibraryLoader.class.getResourceAsStream(resourcePath)) {
                if (in == null) {
                    throw new UnsatisfiedLinkError("Native pkcs11j library not found on classpath at " + resourcePath
                            + " (you may also specify -Dpkcs11j.native.lib=/path/to/libpkcs11j." + ext + ")");
                }
                Path tempDir = Files.createTempDirectory("pkcs11j-native-");
                tempDir.toFile().deleteOnExit();
                Path libFile = tempDir.resolve("libpkcs11j." + ext);
                libFile.toFile().deleteOnExit();
                Files.copy(in, libFile, StandardCopyOption.REPLACE_EXISTING);
                System.load(libFile.toAbsolutePath().toString());
                LOADED.set(true);
            } catch (IOException e) {
                throw new IllegalStateException("Failed to extract native pkcs11j library from " + resourcePath, e);
            }
        }
    }

    static String detectOs() {
        String raw = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (raw.contains("mac") || raw.contains("darwin")) {
            return "osx";
        }
        if (raw.contains("linux")) {
            return "linux";
        }
        throw new UnsupportedOperationException("Unsupported OS for pkcs11j native JNI: " + raw);
    }

    static String detectArch() {
        String raw = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        if ("arm64".equals(raw) || "aarch64".equals(raw)) {
            return "aarch64";
        }
        if ("amd64".equals(raw) || "x86_64".equals(raw)) {
            return "x86_64";
        }
        return raw;
    }
}

