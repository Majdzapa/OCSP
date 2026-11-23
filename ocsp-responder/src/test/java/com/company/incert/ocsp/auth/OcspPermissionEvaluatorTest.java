package com.company.incert.ocsp.auth;

import com.company.incert.ocsp.auth.security.OcspPermissionEvaluator;
import com.company.incert.ocsp.auth.security.SecurityPermissions;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OcspPermissionEvaluatorTest {

    private final OcspPermissionEvaluator evaluator = new OcspPermissionEvaluator();

    @Test
    void adminHasAllPermissions() {
        var auth = new UsernamePasswordAuthenticationToken("admin", null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));
        for (SecurityPermissions perm : SecurityPermissions.values()) {
            assertThat(evaluator.hasPermission(auth, null, perm.name())).isTrue();
        }
    }

    @Test
    void agentCanCreateCsrAndImportButCannotActivateOrManageUsersOrTrustedCas() {
        var auth = new UsernamePasswordAuthenticationToken("agent", null, List.of(new SimpleGrantedAuthority("ROLE_AGENT")));
        assertThat(evaluator.hasPermission(auth, null, "SIGNING_CERT_CREATE_CSR")).isTrue();
        assertThat(evaluator.hasPermission(auth, null, "SIGNING_CERT_IMPORT")).isTrue();
        assertThat(evaluator.hasPermission(auth, null, "CRYPTO_DEVICE_READ")).isTrue();
        assertThat(evaluator.hasPermission(auth, null, "TRUSTED_CA_READ")).isTrue();

        assertThat(evaluator.hasPermission(auth, null, "SIGNING_CERT_ACTIVATE")).isFalse();
        assertThat(evaluator.hasPermission(auth, null, "CRYPTO_DEVICE_MANAGE")).isFalse();
        assertThat(evaluator.hasPermission(auth, null, "USER_MANAGE")).isFalse();
        assertThat(evaluator.hasPermission(auth, null, "TRUSTED_CA_MANAGE")).isFalse();
    }

    @Test
    void auditorHasReadOnlyPermissions() {
        var auth = new UsernamePasswordAuthenticationToken("auditor", null, List.of(new SimpleGrantedAuthority("ROLE_AUDITOR")));
        assertThat(evaluator.hasPermission(auth, null, "DASHBOARD_READ")).isTrue();
        assertThat(evaluator.hasPermission(auth, null, "CRYPTO_DEVICE_READ")).isTrue();
        assertThat(evaluator.hasPermission(auth, null, "TRUSTED_CA_READ")).isTrue();
        assertThat(evaluator.hasPermission(auth, null, "CRYPTO_DEVICE_MANAGE")).isFalse();
        assertThat(evaluator.hasPermission(auth, null, "SIGNING_CERT_CREATE_CSR")).isFalse();
        assertThat(evaluator.hasPermission(auth, null, "INBOX_REPLAY")).isFalse();
    }
}

