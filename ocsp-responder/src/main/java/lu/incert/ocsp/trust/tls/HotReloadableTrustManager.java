package lu.incert.ocsp.trust.tls;

import lu.incert.ocsp.trust.service.TrustedCaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Dynamic, zero-restart {@link X509TrustManager} wired directly into Tomcat's native HTTPS mTLS connector.
 * <ul>
 *   <li>{@link #getAcceptedIssuers()} returns the live list of enabled Trusted CAs from {@link TrustedCaService}
 *       so the TLS {@code CertificateRequest} filters the browser's certificate picker automatically.</li>
 *   <li>{@link #checkClientTrusted(X509Certificate[], String)} validates the presented client certificate chain
 *       against a fresh PKIX truststore built from the live Trusted CAs.</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class HotReloadableTrustManager implements X509TrustManager {

    private final TrustedCaService trustedCaService;

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("No client certificate presented");
        }
        List<X509Certificate> cas = trustedCaService.getActiveTrustedCas();
        if (cas.isEmpty()) {
            throw new CertificateException("No active Trusted CAs configured in truststore");
        }
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            for (int i = 0; i < cas.size(); i++) {
                ks.setCertificateEntry("trusted-ca-" + i, cas.get(i));
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager x509Tm) {
                    x509Tm.checkClientTrusted(chain, authType);
                    return;
                }
            }
            throw new CertificateException("No X509TrustManager available");
        } catch (CertificateException ce) {
            throw ce;
        } catch (Exception e) {
            throw new CertificateException("Client certificate trust validation failed: " + e.getMessage(), e);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        // Server-side mTLS trust manager only validates client certificates
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        List<X509Certificate> cas = trustedCaService.getActiveTrustedCas();
        return cas.toArray(new X509Certificate[0]);
    }
}

