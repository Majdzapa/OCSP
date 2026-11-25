package lu.incert.ocsp.shared.web;

import lu.incert.ocsp.shared.config.AppSecurityProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Opens a dedicated Tomcat connector on {@code security.port-isolation.admin-port} when
 * L4 Data Plane / Control Plane port isolation is enabled.
 * <p>
 * If native Tomcat HTTPS/mTLS ({@code TomcatNativeMtlsConfig}) is already bound to the same
 * {@code admin-port} (for example port {@code 8443}), this customizer reuses that HTTPS/mTLS
 * connector without binding a duplicate plain HTTP port.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class ManagementPortConnectorConfig {

    private final AppSecurityProperties securityProperties;

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> managementPortConnectorCustomizer() {
        return factory -> {
            AppSecurityProperties.PortIsolation isolation = securityProperties.getPortIsolation();
            if (isolation == null || !isolation.isEnabled()) {
                return;
            }

            int ocspPort = isolation.getOcspPort();
            int adminPort = isolation.getAdminPort();
            if (adminPort <= 0 || adminPort == ocspPort) {
                throw new IllegalStateException(
                        "security.port-isolation.admin-port (" + adminPort
                                + ") must be a valid port distinct from ocsp-port (" + ocspPort + ")");
            }

            AppSecurityProperties.Tls tls = securityProperties.getTls();
            boolean mtlsOwnsAdminPort = tls != null
                    && tls.isClientCertAuthEnabled()
                    && tls.getKeyStore() != null
                    && !tls.getKeyStore().isBlank()
                    && tls.getHttpsPort() == adminPort;

            if (mtlsOwnsAdminPort) {
                log.info("Port isolation ACTIVE: public OCSP on port {}, management console/API bound to native HTTPS/mTLS connector on port {}",
                        ocspPort, adminPort);
                return;
            }

            Connector adminConnector = new Connector(Http11NioProtocol.class.getName());
            adminConnector.setScheme("http");
            adminConnector.setSecure(false);
            adminConnector.setPort(adminPort);
            factory.addAdditionalConnectors(adminConnector);
            log.info("Port isolation ACTIVE: public OCSP on port {}, dedicated management connector started on port {} (/console/**, /api/**, /docs/**, /actuator/**)",
                    ocspPort, adminPort);
        };
    }
}
