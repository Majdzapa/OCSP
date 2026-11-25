package lu.incert.ocsp.signing.provider;

import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Security guard enforcing that DB-configured PKCS#11 drivers and JNI wrapper binaries
 * can only be loaded from explicitly allowlisted host directories (mitigating arbitrary {@code dlopen} RCE).
 * <p>
 * Path parsing and normalization are platform-independent so both POSIX paths ({@code /usr/lib/...})
 * and Windows drive-letter paths ({@code C:\SoftHSM2\lib\...}) are validated consistently regardless
 * of the host JVM operating system.
 */
public final class LibraryPathAllowlist {

    private final List<NormalizedPath> allowedDirs;
    private final String defaultWrapperPath;

    public LibraryPathAllowlist(List<String> directories) {
        this(directories, null);
    }

    public LibraryPathAllowlist(List<String> directories, String defaultWrapperPath) {
        if (directories == null || directories.isEmpty()) {
            this.allowedDirs = List.of();
        } else {
            this.allowedDirs = directories.stream()
                    .filter(Objects::nonNull)
                    .map(String::trim)
                    .filter(s -> !s.isBlank())
                    .map(LibraryPathAllowlist::normalizeDirectoryEntry)
                    .distinct()
                    .toList();
        }
        String trimmedDefault = (defaultWrapperPath == null || defaultWrapperPath.isBlank())
                ? null
                : defaultWrapperPath.trim();
        if (trimmedDefault != null && !"embedded".equalsIgnoreCase(trimmedDefault) && !"auto".equalsIgnoreCase(trimmedDefault)) {
            this.defaultWrapperPath = validateNormalizedAbsoluteFile(trimmedDefault, "hsm.default-wrapper-path");
        } else {
            this.defaultWrapperPath = null;
        }
    }

    public String validateLibraryPath(String libraryPath) {
        if (libraryPath == null || libraryPath.isBlank()) {
            throw new IllegalArgumentException("libraryPath must not be blank");
        }
        return validateNormalizedAbsoluteFile(libraryPath, "libraryPath");
    }

    /**
     * Validates an optional explicit JNI wrapper path.
     * Returns {@code null} when blank/{@code embedded}/{@code auto} and no {@code hsm.default-wrapper-path}
     * is configured (instructing {@code ipkcs11wrapper} to use its built-in OS/arch native loader).
     */
    public String validateWrapperPath(String wrapperPath) {
        if (wrapperPath == null || wrapperPath.isBlank()) {
            return defaultWrapperPath;
        }
        String trimmed = wrapperPath.trim();
        if ("embedded".equalsIgnoreCase(trimmed) || "auto".equalsIgnoreCase(trimmed)) {
            return defaultWrapperPath;
        }
        return validateNormalizedAbsoluteFile(trimmed, "libraryWrapperPath");
    }

    public List<String> getAllowedDirectories() {
        return allowedDirs.stream().map(NormalizedPath::display).toList();
    }

    private String validateNormalizedAbsoluteFile(String rawPath, String fieldName) {
        String trimmed = rawPath.trim();
        if (trimmed.indexOf('\0') >= 0) {
            throw new IllegalArgumentException(fieldName + " must not contain null characters");
        }
        if (trimmed.startsWith("//") || trimmed.startsWith("\\\\")) {
            throw new IllegalArgumentException(fieldName + " must be a local absolute path (UNC paths are not permitted): '" + trimmed + "'");
        }
        boolean posix = isPosixAbsolute(trimmed);
        boolean windows = isWindowsDriveAbsolute(trimmed);
        if (!posix && !windows) {
            throw new IllegalArgumentException(fieldName + " must be an absolute path: '" + trimmed + "'");
        }
        if (trimmed.contains("..")) {
            throw new IllegalArgumentException(fieldName + " must not contain path traversal segments: '" + trimmed + "'");
        }
        if (posix && trimmed.indexOf('\\') >= 0) {
            throw new IllegalArgumentException(fieldName + " must not mix backslashes in a POSIX path: '" + trimmed + "'");
        }
        if (allowedDirs.isEmpty()) {
            throw new IllegalStateException("No hsm.allowed-library-dirs configured; refusing to load native library");
        }
        NormalizedPath normalized = posix
                ? normalizePosix(trimmed)
                : normalizeWindows(trimmed);
        boolean permitted = allowedDirs.stream().anyMatch(dir -> dir.containsFile(normalized));
        if (!permitted) {
            throw new IllegalArgumentException(fieldName + " '" + normalized.display()
                    + "' is outside hsm.allowed-library-dirs " + getAllowedDirectories());
        }
        return normalized.display();
    }

    private static NormalizedPath normalizeDirectoryEntry(String raw) {
        if (isPosixAbsolute(raw)) {
            return normalizePosix(raw);
        }
        if (isWindowsDriveAbsolute(raw)) {
            return normalizeWindows(raw);
        }
        String resolved = Path.of(raw).toAbsolutePath().normalize().toString();
        return isWindowsDriveAbsolute(resolved) ? normalizeWindows(resolved) : normalizePosix(resolved);
    }

    private static boolean isPosixAbsolute(String path) {
        return path.startsWith("/") && !path.startsWith("//");
    }

    private static boolean isWindowsDriveAbsolute(String path) {
        if (path.length() < 3) {
            return false;
        }
        char drive = path.charAt(0);
        boolean asciiLetter = (drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z');
        return asciiLetter && path.charAt(1) == ':' && (path.charAt(2) == '\\' || path.charAt(2) == '/');
    }

    private static NormalizedPath normalizePosix(String path) {
        Deque<String> segments = new ArrayDeque<>();
        for (String part : path.split("/")) {
            if (part.isEmpty() || ".".equals(part)) {
                continue;
            }
            if ("..".equals(part)) {
                if (!segments.isEmpty()) {
                    segments.removeLast();
                }
            } else {
                segments.addLast(part);
            }
        }
        String canonical = segments.isEmpty() ? "/" : "/" + String.join("/", segments);
        return new NormalizedPath(PathStyle.POSIX, canonical, canonical);
    }

    private static NormalizedPath normalizeWindows(String path) {
        char driveUpper = Character.toUpperCase(path.charAt(0));
        String rest = path.substring(2).replace('\\', '/');
        Deque<String> segments = new ArrayDeque<>();
        for (String part : rest.split("/")) {
            if (part.isEmpty() || ".".equals(part)) {
                continue;
            }
            if ("..".equals(part)) {
                if (!segments.isEmpty()) {
                    segments.removeLast();
                }
            } else {
                segments.addLast(part);
            }
        }
        String display = segments.isEmpty()
                ? driveUpper + ":\\"
                : driveUpper + ":\\" + String.join("\\", segments);
        String key = segments.isEmpty()
                ? Character.toLowerCase(driveUpper) + ":/"
                : Character.toLowerCase(driveUpper) + ":/" + String.join("/", segments).toLowerCase(Locale.ROOT);
        return new NormalizedPath(PathStyle.WINDOWS, display, key);
    }

    private enum PathStyle {
        POSIX, WINDOWS
    }

    private record NormalizedPath(PathStyle style, String display, String comparisonKey) {
        boolean containsFile(NormalizedPath candidate) {
            if (this.style != candidate.style) {
                return false;
            }
            if (this.comparisonKey.equals(candidate.comparisonKey)) {
                return false;
            }
            String prefix = this.comparisonKey.endsWith("/") ? this.comparisonKey : this.comparisonKey + "/";
            return candidate.comparisonKey.startsWith(prefix);
        }
    }
}

