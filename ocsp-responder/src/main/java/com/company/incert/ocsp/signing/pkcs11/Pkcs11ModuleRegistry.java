package com.company.incert.ocsp.signing.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Reference-counted registry ensuring each PKCS#11 shared library is initialized once via
 * {@code C_Initialize(CKF_OS_LOCKING_OK)} and finalized via {@code C_Finalize} only when the last
 * slot/provider referencing that module closes.
 */
final class Pkcs11ModuleRegistry {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11ModuleRegistry.class);

    private final BiFunction<String, String, Pkcs11LibraryPort> libraryFactory;
    private final Map<String, LoadedModule> modulesByPath = new ConcurrentHashMap<>();

    Pkcs11ModuleRegistry(Function<String, Pkcs11LibraryPort> libraryFactory) {
        this((libPath, wrapperPath) -> Objects.requireNonNull(libraryFactory, "libraryFactory must not be null")
                .apply(libPath));
    }

    Pkcs11ModuleRegistry(BiFunction<String, String, Pkcs11LibraryPort> libraryFactory) {
        this.libraryFactory = Objects.requireNonNull(libraryFactory, "libraryFactory must not be null");
    }

    Pkcs11LibraryPort acquire(String libraryPath, String libraryWrapperPath) {
        String canonical = canonicalize(libraryPath);
        LoadedModule entry = modulesByPath.compute(canonical, (path, existing) -> {
            if (existing != null) {
                existing.refCount++;
                return existing;
            }
            Pkcs11LibraryPort port = libraryFactory.apply(path, libraryWrapperPath);
            try {
                long rv = port.cInitialize(Pkcs11Constants.CKF_OS_LOCKING_OK);
                if (rv != Pkcs11Constants.CKR_OK && rv != Pkcs11Constants.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
                    throw new Pkcs11Exception("C_Initialize", rv);
                }
                log.info("Initialized PKCS#11 module '{}' (wrapper='{}') via C_Initialize (rv={})",
                        path, libraryWrapperPath, Pkcs11Constants.errorName(rv));
            } catch (RuntimeException e) {
                safeClose(port);
                throw e;
            }
            return new LoadedModule(port, 1);
        });
        return entry.port;
    }

    void release(String libraryPath) {
        String canonical = canonicalize(libraryPath);
        modulesByPath.computeIfPresent(canonical, (path, existing) -> {
            existing.refCount--;
            if (existing.refCount > 0) {
                return existing;
            }
            try {
                long rv = existing.port.cFinalize();
                log.info("Finalized PKCS#11 module '{}' via C_Finalize (rv={})",
                        path, Pkcs11Constants.errorName(rv));
            } catch (Exception e) {
                log.warn("C_Finalize failed for module '{}': {}", path, e.getMessage());
            } finally {
                safeClose(existing.port);
            }
            return null;
        });
    }

    int loadedModuleCount() {
        return modulesByPath.size();
    }

    private static String canonicalize(String path) {
        return Path.of(path.trim()).toAbsolutePath().normalize().toString();
    }

    private static void safeClose(Pkcs11LibraryPort port) {
        try {
            port.close();
        } catch (Exception ignored) {}
    }

    private static final class LoadedModule {
        final Pkcs11LibraryPort port;
        int refCount;

        LoadedModule(Pkcs11LibraryPort port, int refCount) {
            this.port = port;
            this.refCount = refCount;
        }
    }
}

