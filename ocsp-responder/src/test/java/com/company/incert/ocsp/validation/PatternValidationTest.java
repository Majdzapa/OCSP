package com.company.incert.ocsp.validation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PatternValidationTest {

    @Test
    void validatesUsernamesEmailsPasswordsHexAndFingerprints() {
        assertThat(PatternValidation.isValidUsername("admin")).isTrue();
        assertThat(PatternValidation.isValidUsername("john.doe_1-a")).isTrue();
        assertThat(PatternValidation.isValidUsername("ab")).isFalse();
        assertThat(PatternValidation.isValidUsername("bad user!")).isFalse();

        assertThat(PatternValidation.isValidEmail("user@incert.local")).isTrue();
        assertThat(PatternValidation.isValidEmail("bad-email")).isFalse();

        assertThat(PatternValidation.isValidPassword("changeme")).isTrue();
        assertThat(PatternValidation.isValidPassword("123")).isFalse();
        assertThatThrownBy(() -> PatternValidation.requireValidPassword("   "))
                .isInstanceOf(IllegalArgumentException.class);

        assertThat(PatternValidation.isValidHexSerial("0x1a2b3c")).isTrue();
        assertThat(PatternValidation.isValidHexSerial("1A:2B:3C")).isTrue();
        assertThat(PatternValidation.isValidHexSerial("xyz")).isFalse();

        assertThat(PatternValidation.isValidSha256Fingerprint("a".repeat(64))).isTrue();
        assertThat(PatternValidation.isValidSha256Fingerprint("a".repeat(63))).isFalse();
    }
}

