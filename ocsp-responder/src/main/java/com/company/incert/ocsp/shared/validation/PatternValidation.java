package com.company.incert.ocsp.shared.validation;

import java.util.regex.Pattern;

/**
 * Centralized compiled {@link Pattern} matchers and validation helpers for user identity,
 * credentials, and X.509 certificate identifiers.
 */
public final class PatternValidation {

    public static final String USERNAME_REGEX = "^[a-zA-Z0-9._-]{3,100}$";
    public static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
    public static final String PASSWORD_REGEX = "^.{4,128}$";
    public static final String HEX_SERIAL_REGEX = "^(?:0x)?[0-9a-fA-F: ]+$";
    public static final String SHA256_FINGERPRINT_REGEX = "^[0-9a-fA-F]{64}$";

    public static final Pattern USERNAME_PATTERN = Pattern.compile(USERNAME_REGEX);
    public static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);
    public static final Pattern PASSWORD_PATTERN = Pattern.compile(PASSWORD_REGEX);
    public static final Pattern HEX_SERIAL_PATTERN = Pattern.compile(HEX_SERIAL_REGEX);
    public static final Pattern SHA256_FINGERPRINT_PATTERN = Pattern.compile(SHA256_FINGERPRINT_REGEX);

    private PatternValidation() {
    }

    public static boolean isValidUsername(String username) {
        return username != null && USERNAME_PATTERN.matcher(username.trim()).matches();
    }

    public static String requireValidUsername(String username) {
        if (!isValidUsername(username)) {
            throw new IllegalArgumentException(
                    "Username must be 3-100 characters and contain only letters, digits, '.', '_', or '-'");
        }
        return username.trim();
    }

    public static boolean isValidEmail(String email) {
        return email != null && EMAIL_PATTERN.matcher(email.trim()).matches();
    }

    public static String normalizeAndValidateOptionalEmail(String email) {
        if (email == null || email.isBlank()) {
            return null;
        }
        String trimmed = email.trim();
        if (!EMAIL_PATTERN.matcher(trimmed).matches()) {
            throw new IllegalArgumentException("Invalid email format");
        }
        return trimmed;
    }

    public static boolean isValidPassword(String password) {
        return password != null && !password.isBlank() && PASSWORD_PATTERN.matcher(password).matches();
    }

    public static String requireValidPassword(String password) {
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("Password is required");
        }
        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new IllegalArgumentException("Password must be between 4 and 128 characters");
        }
        return password;
    }

    public static boolean isValidHexSerial(String serialHex) {
        return serialHex != null && !serialHex.isBlank() && HEX_SERIAL_PATTERN.matcher(serialHex.trim()).matches();
    }

    public static boolean isValidSha256Fingerprint(String fingerprint) {
        return fingerprint != null && SHA256_FINGERPRINT_PATTERN.matcher(fingerprint.trim()).matches();
    }
}

