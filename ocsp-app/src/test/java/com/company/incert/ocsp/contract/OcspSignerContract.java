package com.company.incert.ocsp.contract;

import com.company.incert.ocsp.signing.application.port.out.OcspSigner;
import org.bouncycastle.operator.ContentSigner;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Abstract contract test for OcspSigner port implementations.
 * Verifies that any adapter satisfies the contract (Liskov Substitution Principle).
 */
public abstract class OcspSignerContract {

    protected abstract OcspSigner createSigner() throws Exception;

    @Test
    void shouldCreateContentSigner() throws Exception {
        OcspSigner signer = createSigner();
        ContentSigner contentSigner = signer.createContentSigner();
        assertThat(contentSigner).isNotNull();
        assertThat(contentSigner.getOutputStream()).isNotNull();
    }

    @Test
    void shouldProvideSignerCertificateChain() throws Exception {
        OcspSigner signer = createSigner();
        assertThat(signer.getSignerChain()).isNotEmpty();
        assertThat(signer.getSignerChain()[0]).isNotNull();
    }

    @Test
    void shouldReportExpiryDays() throws Exception {
        OcspSigner signer = createSigner();
        assertThat(signer.signingCertDaysUntilExpiry()).isGreaterThanOrEqualTo(0);
    }
}

