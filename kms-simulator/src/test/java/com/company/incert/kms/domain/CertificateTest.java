package com.company.incert.kms.domain;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateTest {

    @Test
    void certificateRecordEquality() {
        Certificate c = new Certificate(
                "abc123", "CN=Test CA", "keyhash", "namehash",
                "CN=Test", Instant.EPOCH, Instant.MAX,
                CertificateStatus.GOOD, null, null, "PEM", 0
        );
        assertThat(c.serialNumberHex()).isEqualTo("abc123");
        assertThat(c.status()).isEqualTo(CertificateStatus.GOOD);
    }

    @Test
    void eventFromCertificatePopulatesFields() {
        Certificate c = new Certificate(
                "serial1", "CN=CA", "khex", "nhex", "CN=EE",
                Instant.EPOCH, Instant.MAX,
                CertificateStatus.REVOKED, Instant.now(), RevocationReason.KEY_COMPROMISE,
                "PEM", 2
        );
        CertificateStatusChangedEvent event = CertificateStatusChangedEvent.from(c);
        assertThat(event.eventType()).isEqualTo("CertificateStatusChanged");
        assertThat(event.serialNumberHex()).isEqualTo("serial1");
        assertThat(event.status()).isEqualTo(CertificateStatus.REVOKED);
        assertThat(event.revocationReason()).isEqualTo(RevocationReason.KEY_COMPROMISE);
        assertThat(event.schemaVersion()).isEqualTo(1);
        assertThat(event.sequence()).isEqualTo(2);
        assertThat(event.eventId()).isNotBlank();
    }

    @Test
    void revocationReasonCodesAreCorrect() {
        assertThat(RevocationReason.UNSPECIFIED.getCode()).isZero();
        assertThat(RevocationReason.KEY_COMPROMISE.getCode()).isEqualTo(1);
        assertThat(RevocationReason.CERTIFICATE_HOLD.getCode()).isEqualTo(6);
        assertThat(RevocationReason.AA_COMPROMISE.getCode()).isEqualTo(10);
    }
}
