package com.company.incert.kms.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateTest {

    @Test
    void certificateEntityCreation() {
        Certificate c = Certificate.builder()
                .serialNumberHex("abc123")
                .issuerDn("CN=Test CA")
                .issuerKeyHashHex("keyhash")
                .issuerNameHashHex("namehash")
                .subjectDn("CN=Test")
                .notBefore(Instant.EPOCH)
                .notAfter(Instant.MAX)
                .status(CertificateStatus.GOOD)
                .pemEncoded("PEM")
                .sequence(0L)
                .build();

        assertThat(c.getSerialNumberHex()).isEqualTo("abc123");
        assertThat(c.getStatus()).isEqualTo(CertificateStatus.GOOD);
    }

    @Test
    void eventFromCertificatePopulatesFields() {
        Certificate c = Certificate.builder()
                .serialNumberHex("serial1")
                .issuerDn("CN=CA")
                .issuerKeyHashHex("khex")
                .issuerNameHashHex("nhex")
                .subjectDn("CN=EE")
                .notBefore(Instant.EPOCH)
                .notAfter(Instant.MAX)
                .status(CertificateStatus.REVOKED)
                .revocationTime(Instant.now())
                .revocationReason(RevocationReason.KEY_COMPROMISE)
                .pemEncoded("PEM")
                .sequence(2L)
                .build();

        CertificateStatusEvent event = CertificateStatusEvent.from(c);
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

