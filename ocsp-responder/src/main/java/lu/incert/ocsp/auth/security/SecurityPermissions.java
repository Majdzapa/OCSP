package lu.incert.ocsp.auth.security;

import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * Fine-grained RBAC permissions evaluated via Spring Security {@code hasPermission(null, '<PERMISSION>')}.
 */
public enum SecurityPermissions {

    // Dashboard & Audit
    DASHBOARD_READ,
    REVOCATION_READ,
    INBOX_READ,
    INBOX_REPLAY,
    CERT_CHECK_READ,

    // Signing Certificates & HSM
    SIGNING_CERT_READ,
    SIGNING_CERT_CREATE_CSR,
    SIGNING_CERT_IMPORT,
    SIGNING_CERT_ACTIVATE,
    SIGNING_CERT_DEACTIVATE,
    SIGNING_CERT_DELETE,
    SIGNING_CERT_VALIDITY_CHECK,
    SIGNING_CERT_RENEW,

    // Cryptographic Providers & HSM Devices (DB + Runtime Activation)
    CRYPTO_DEVICE_READ,
    CRYPTO_DEVICE_MANAGE,

    // Trusted CAs (mTLS client-certificate truststore)
    TRUSTED_CA_READ,
    TRUSTED_CA_MANAGE,

    // User & Certificate Assignment Management
    USER_READ,
    USER_MANAGE;

    private static final Set<SecurityPermissions> AUDITOR_PERMISSIONS = EnumSet.of(
            DASHBOARD_READ,
            REVOCATION_READ,
            INBOX_READ,
            CERT_CHECK_READ,
            SIGNING_CERT_READ,
            CRYPTO_DEVICE_READ,
            TRUSTED_CA_READ
    );

    private static final Set<SecurityPermissions> AGENT_PERMISSIONS = EnumSet.of(
            DASHBOARD_READ,
            REVOCATION_READ,
            INBOX_READ,
            INBOX_REPLAY,
            CERT_CHECK_READ,
            SIGNING_CERT_READ,
            SIGNING_CERT_CREATE_CSR,
            SIGNING_CERT_IMPORT,
            SIGNING_CERT_VALIDITY_CHECK,
            SIGNING_CERT_RENEW,
            CRYPTO_DEVICE_READ,
            TRUSTED_CA_READ
    );

    private static final Map<String, Set<SecurityPermissions>> ROLE_PERMISSIONS = Map.of(
            "ROLE_ADMIN", EnumSet.allOf(SecurityPermissions.class),
            "ROLE_AGENT", AGENT_PERMISSIONS,
            "ROLE_OPERATOR", AGENT_PERMISSIONS,
            "ROLE_AUDITOR", AUDITOR_PERMISSIONS
    );

    public static Set<SecurityPermissions> forRole(String roleName) {
        if (roleName == null) {
            return Set.of();
        }
        String normalized = roleName.trim().toUpperCase();
        if (!normalized.startsWith("ROLE_")) {
            normalized = "ROLE_" + normalized;
        }
        return ROLE_PERMISSIONS.getOrDefault(normalized, Set.of());
    }
}

