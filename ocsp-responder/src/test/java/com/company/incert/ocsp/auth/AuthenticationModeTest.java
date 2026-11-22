package com.company.incert.ocsp.auth;


import com.company.incert.ocsp.auth.config.AuthenticationMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationModeTest {

    @ParameterizedTest
    @ValueSource(strings = {"KEYCLOAK", "keycloak", "KeyCloak", " KEYCLOAK "})
    void keycloakSpellingIsRecognized(String raw) {
        AuthenticationMode mode = AuthenticationMode.fromString(raw);
        assertThat(mode).isEqualTo(AuthenticationMode.KEYCLOAK);
        assertThat(mode.isKeycloak()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"KEYCLOCK", "keyclock", "KeyClock", " KEYCLOCK "})
    void legacyKeyclockTypoIsNormalizedToKeycloak(String raw) {
        AuthenticationMode mode = AuthenticationMode.fromString(raw);
        assertThat(mode).isEqualTo(AuthenticationMode.KEYCLOAK);
        assertThat(mode.isKeycloak()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"OIDC", "oidc", "OAUTH2", "oauth2"})
    void oidcAliasesResolveToKeycloak(String raw) {
        assertThat(AuthenticationMode.fromString(raw).isKeycloak()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"SELF_MANAGEMENT", "self_management", "SELF_MANAGED", "self_managed"})
    void selfManagementResolvesCorrectly(String raw) {
        AuthenticationMode mode = AuthenticationMode.fromString(raw);
        assertThat(mode).isEqualTo(AuthenticationMode.SELF_MANAGEMENT);
        assertThat(mode.isKeycloak()).isFalse();
    }
}
