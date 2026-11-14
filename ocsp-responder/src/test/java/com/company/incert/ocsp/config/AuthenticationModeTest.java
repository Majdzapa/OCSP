package com.company.incert.ocsp.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationModeTest {

    @ParameterizedTest
    @ValueSource(strings = {"KEYCLOCK", "keyclock", "KeyClock", " KEYCLOCK "})
    void fromString_keycloakVariants_resolvesToKeycloak(String input) {
        AuthenticationMode mode = AuthenticationMode.fromString(input);
        assertThat(mode).isEqualTo(AuthenticationMode.KEYCLOCK);
        assertThat(mode.isKeycloak()).isTrue();
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
}

