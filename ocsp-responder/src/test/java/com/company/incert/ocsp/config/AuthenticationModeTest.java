package com.company.incert.ocsp.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationModeTest {

    @ParameterizedTest
    @ValueSource(strings = {"KEYCLOAK", "keycloak", "KeyCloak", " KEYCLOAK "})
    void fromString_keycloakVariants_resolvesToKeycloak(String input) {
        AuthenticationMode mode = AuthenticationMode.fromString(input);
        assertThat(mode).isEqualTo(AuthenticationMode.KEYCLOAK);
        assertThat(mode.isKeycloak()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"KEYCLOCK", "keyclock", "KeyClock", " KEYCLOCK "})
    void fromString_legacyKeyclockAlias_resolvesToKeycloak(String input) {
        // KEYCLOCK is a deprecated alias — fromString must still resolve it correctly
        AuthenticationMode mode = AuthenticationMode.fromString(input);
        assertThat(mode).isEqualTo(AuthenticationMode.KEYCLOAK);
        assertThat(mode.isKeycloak()).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"OIDC", "oidc", "OAUTH2", "oauth2"})
    void fromString_oidcOauth2Aliases_resolvesToKeycloak(String input) {
        assertThat(AuthenticationMode.fromString(input)).isEqualTo(AuthenticationMode.KEYCLOAK);
    }

    @ParameterizedTest
    @ValueSource(strings = {"SELF_MANAGED", "self_managed", "Self_Managed", " SELF_MANAGED "})
    void fromString_selfManagedVariants_resolvesToSelfManaged(String input) {
        AuthenticationMode mode = AuthenticationMode.fromString(input);
        assertThat(mode).isEqualTo(AuthenticationMode.SELF_MANAGED);
        assertThat(mode.isKeycloak()).isFalse();
    }

    @Test
    void fromString_nullOrEmptyOrUnknown_defaultsToSelfManaged() {
        assertThat(AuthenticationMode.fromString(null)).isEqualTo(AuthenticationMode.SELF_MANAGED);
        assertThat(AuthenticationMode.fromString("")).isEqualTo(AuthenticationMode.SELF_MANAGED);
        assertThat(AuthenticationMode.fromString("   ")).isEqualTo(AuthenticationMode.SELF_MANAGED);
        assertThat(AuthenticationMode.fromString("OAUTH2_UNKNOWN")).isEqualTo(AuthenticationMode.SELF_MANAGED);
    }

    @Test
    void keyclock_isDeprecatedAlias_forKeycloak() {
        // Both enum constants must report isKeycloak() = true
        assertThat(AuthenticationMode.KEYCLOAK.isKeycloak()).isTrue();
        assertThat(AuthenticationMode.KEYCLOCK.isKeycloak()).isTrue();
    }
}
