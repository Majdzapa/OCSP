package lu.incert.ocsp.responder.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/** OCSP response and parser limits ({@code ocsp.responder.*}), bound from {@code application*.yml}. */
@Getter
@Setter
@ConfigurationProperties(prefix = "ocsp.responder")
public class OcspResponderProperties {

    /** Validity window written into {@code nextUpdate} of every signed response. */
    private Duration nextUpdateWindow;

    /** Maximum DER request size accepted in bytes. */
    private int maxRequestBytes;

    /** Maximum number of CertIDs answered in a single request. */
    private int maxCertIds;

    /** Maximum RFC 8954 nonce length in octets. */
    private int maxNonceOctets;
}
