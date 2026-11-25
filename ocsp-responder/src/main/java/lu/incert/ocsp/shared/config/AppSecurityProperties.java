package lu.incert.ocsp.shared.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/** Login TLS, native Tomcat mTLS connector, port isolation, and CORS ({@code security.*}), bound from {@code application*.yml}. */
@Getter
@Setter
@ConfigurationProperties(prefix = "security")
public class AppSecurityProperties {

    private Tls tls = new Tls();
    private Cors cors = new Cors();
    private PortIsolation portIsolation = new PortIsolation();

    @Getter
    @Setter
    public static class Tls {
        private boolean enabled;
        private boolean clientCertAuthEnabled;
        private int httpsPort = 8443;
        private String keyStore;
        private String keyStorePassword;
        private String keyStoreType = "PKCS12";
    }

    @Getter
    @Setter
    public static class Cors {
        private List<String> allowedOrigins = new ArrayList<>();
    }

    /**
     * L4 Data Plane / Control Plane port isolation for high-security PKI deployments.
     * When {@code enabled=true}, {@code ocspPort} (e.g. 8080) serves ONLY RFC 6960 {@code /ocsp}
     * and {@code /ocsp/health}, while {@code adminPort} (e.g. 8443 HTTPS/mTLS or 9090 internal HTTP)
     * serves {@code /console/**}, {@code /api/**}, {@code /docs/**}, and {@code /actuator/**}.
     */
    @Getter
    @Setter
    public static class PortIsolation {
        private boolean enabled = false;
        private int ocspPort = 8080;
        private int adminPort = 9090;
    }
}
