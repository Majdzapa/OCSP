package lu.incert.ocsp.signing.hsm;

/**
 * Thrown when the OCSP responder has active signing certificate(s) configured,
 * but none of them is authorized (issued by or directly belonging to) the Issuing CA
 * identified in the incoming RFC 6960 {@code CertificateID}.
 * <p>
 * The responder maps this to the unsigned RFC 6960 {@code unauthorized (6)} response
 * status without touching the HSM or signing a response that would fail client-side
 * Responder Authorization (RFC 6960 §4.2.2.2).
 */
public class UnauthorizedIssuerException extends IllegalStateException {

    public UnauthorizedIssuerException(String message) {
        super(message);
    }
}
