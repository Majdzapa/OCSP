package com.company.incert.ocsp.service;

import com.company.incert.ocsp.dto.GenerateCsrRequest;
import com.company.incert.ocsp.dto.GenerateCsrResponse;
import com.company.incert.ocsp.dto.SigningCertValidityReportDto;
import com.company.incert.ocsp.entity.SigningCertificate;
import com.company.incert.ocsp.repository.SigningCertificateRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SigningCertificateValidityServiceTest {

    @Mock
    private SigningCertificateRepository repository;

    @Mock
    private SigningCertificateService signingCertificateService;

    private SigningCertificateValidityService validityService;

    @BeforeEach
    void setUp() {
        validityService = new SigningCertificateValidityService(repository, signingCertificateService);
    }

    @Test
    void shouldRaiseAlertWhenCertificateExpiresIn3DaysOrLess() {
        Instant now = Instant.now();

        SigningCertificate healthy = SigningCertificate.builder()
                .id(1L)
                .alias("healthy-cert")
                .keyLabel("key-1")
                .subjectDn("CN=Healthy,O=Incert,C=CH")
                .issuerDn("CN=CA,O=Incert,C=CH")
                .serialNumber("01")
                .signatureAlgorithm("SHA256withRSA")
                .notBefore(now.minus(10, ChronoUnit.DAYS))
                .notAfter(now.plus(20, ChronoUnit.DAYS))
                .active(true)
                .build();

        SigningCertificate expiringIn2Days = SigningCertificate.builder()
                .id(2L)
                .alias("expiring-2d-cert")
                .keyLabel("key-2")
                .subjectDn("CN=ExpiringSoon,O=Incert,C=CH")
                .issuerDn("CN=CA,O=Incert,C=CH")
                .serialNumber("02")
                .signatureAlgorithm("SHA256withECDSA")
                .notBefore(now.minus(28, ChronoUnit.DAYS))
                .notAfter(now.plus(2, ChronoUnit.DAYS))
                .active(true)
                .build();

        SigningCertificate expired = SigningCertificate.builder()
                .id(3L)
                .alias("expired-cert")
                .keyLabel("key-3")
                .subjectDn("CN=Expired,O=Incert,C=CH")
                .issuerDn("CN=CA,O=Incert,C=CH")
                .serialNumber("03")
                .signatureAlgorithm("SHA256withRSA")
                .notBefore(now.minus(40, ChronoUnit.DAYS))
                .notAfter(now.minus(1, ChronoUnit.DAYS))
                .active(false)
                .build();

        when(repository.findAll()).thenReturn(List.of(healthy, expiringIn2Days, expired));

        SigningCertValidityReportDto report = validityService.runDailyValidityCheck();

        assertThat(report.totalCount()).isEqualTo(3);
        assertThat(report.activeCount()).isEqualTo(2);
        assertThat(report.healthyCount()).isEqualTo(1);
        assertThat(report.expiringWithinThresholdCount()).isEqualTo(1);
        assertThat(report.expiredCount()).isEqualTo(1);
        assertThat(report.alertActive()).isTrue();
        assertThat(report.alerts()).hasSize(2);
        assertThat(report.alerts().get(0).alias()).isEqualTo("expiring-2d-cert");
        assertThat(report.alerts().get(0).severity()).isEqualTo("EXPIRING_SOON");
        assertThat(report.alerts().get(1).alias()).isEqualTo("expired-cert");
        assertThat(report.alerts().get(1).severity()).isEqualTo("EXPIRED");
    }

    @Test
    void shouldCreateRenewalCsrReusingExistingHsmKey() {
        Instant now = Instant.now();
        SigningCertificate cert = SigningCertificate.builder()
                .id(10L)
                .alias("ocsp-signer-ec")
                .keyLabel("hsm-ec-key-1")
                .subjectDn("CN=Incert EC Signer,O=Incert,C=CH")
                .issuerDn("CN=Incert CA,O=Incert,C=CH")
                .signatureAlgorithm("SHA256withECDSA")
                .notBefore(now.minus(28, ChronoUnit.DAYS))
                .notAfter(now.plus(2, ChronoUnit.DAYS))
                .active(true)
                .build();

        when(repository.findById(10L)).thenReturn(Optional.of(cert));
        when(signingCertificateService.generateCsr(any())).thenReturn(
                new GenerateCsrResponse("hsm-ec-key-1", "CN=Incert EC Signer,O=Incert,C=CH", "EC", "-----BEGIN CERTIFICATE REQUEST-----")
        );

        GenerateCsrResponse res = validityService.createRenewalRequest(10L, true, null, null);

        assertThat(res.keyLabel()).isEqualTo("hsm-ec-key-1");
        assertThat(res.keyAlgorithm()).isEqualTo("EC");

        ArgumentCaptor<GenerateCsrRequest> captor = ArgumentCaptor.forClass(GenerateCsrRequest.class);
        verify(signingCertificateService).generateCsr(captor.capture());
        assertThat(captor.getValue().keyLabel()).isEqualTo("hsm-ec-key-1");
        assertThat(captor.getValue().subjectDn()).isEqualTo("CN=Incert EC Signer,O=Incert,C=CH");
        assertThat(captor.getValue().keyAlgorithm()).isEqualTo("EC");
        assertThat(captor.getValue().reuseExistingKey()).isTrue();
    }
}

