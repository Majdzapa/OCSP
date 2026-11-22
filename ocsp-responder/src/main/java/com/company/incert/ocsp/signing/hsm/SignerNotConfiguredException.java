package com.company.incert.ocsp.signing.hsm;

/**
 * Thrown when an OCSP response must be signed but no active, non-expired signing certificate is configured.
 * The responder maps this to the RFC 6960 {@code tryLater} status instead of signing with an unconfigured key.
 */
public class SignerNotConfiguredException extends IllegalStateException {

    public SignerNotConfiguredException(String message) {
        super(message);
    }
}

