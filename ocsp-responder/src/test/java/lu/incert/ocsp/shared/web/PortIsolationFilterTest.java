package lu.incert.ocsp.shared.web;

import lu.incert.ocsp.shared.config.AppSecurityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class PortIsolationFilterTest {

    @Test
    void passesAllRequestsThroughWhenDisabled() throws Exception {
        AppSecurityProperties props = new AppSecurityProperties();
        props.getPortIsolation().setEnabled(false);
        PortIsolationFilter filter = new PortIsolationFilter(props);

        for (String uri : new String[]{"/ocsp", "/ocsp/health", "/console/hsm-devices", "/api/v1/admin/crypto-devices", "/actuator/health"}) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", uri);
            req.setLocalPort(8080);
            MockHttpServletResponse res = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(req, res, chain);
            assertThat(res.getStatus()).isEqualTo(200);
            assertThat(chain.getRequest()).isNotNull();
        }
    }

    @Test
    void publicOcspPortOnlyPermitsOcspAndOcspHealthWhenEnabled() throws Exception {
        AppSecurityProperties props = enabledIsolation(8080, 9090);
        PortIsolationFilter filter = new PortIsolationFilter(props);

        for (String allowed : new String[]{"/ocsp", "/ocsp/health", "/ocsp/MFEwTzBNMEswSTAJBgUrDgMCGgU="}) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", allowed);
            req.setLocalPort(8080);
            MockHttpServletResponse res = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(req, res, chain);
            assertThat(res.getStatus()).as("Expected 200 on OCSP port for %s", allowed).isEqualTo(200);
            assertThat(chain.getRequest()).isNotNull();
        }

        for (String blocked : new String[]{
                "/", "/console", "/console/hsm-devices",
                "/api/v1/admin/crypto-devices", "/api/v1/auth/login",
                "/actuator/health", "/docs/ocsp/5.0/index.html", "/swagger-ui/index.html"
        }) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", blocked);
            req.setLocalPort(8080);
            MockHttpServletResponse res = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(req, res, chain);
            assertThat(res.getStatus()).as("Expected 404 on OCSP port for %s", blocked).isEqualTo(404);
            assertThat(chain.getRequest()).isNull();
        }
    }

    @Test
    void adminManagementPortPermitsConsoleApiDocsActuatorAndOcspHealthButBlocksOcspSigning() throws Exception {
        AppSecurityProperties props = enabledIsolation(8080, 9090);
        PortIsolationFilter filter = new PortIsolationFilter(props);

        for (String allowed : new String[]{
                "/", "/console/", "/console/hsm-devices", "/console/assets/index.js",
                "/api/v1/admin/crypto-devices", "/api/v1/auth/login", "/api/v1/client/test",
                "/docs/ocsp/5.0/index.html", "/actuator/health", "/ocsp/health"
        }) {
            MockHttpServletRequest req = new MockHttpServletRequest("GET", allowed);
            req.setLocalPort(9090);
            MockHttpServletResponse res = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(req, res, chain);
            assertThat(res.getStatus()).as("Expected 200 on admin port for %s", allowed).isEqualTo(200);
            assertThat(chain.getRequest()).isNotNull();
        }

        for (String blocked : new String[]{"/ocsp", "/ocsp/MFEwTzBNMEswSTAJBgUrDgMCGgU="}) {
            MockHttpServletRequest req = new MockHttpServletRequest("POST", blocked);
            req.setLocalPort(9090);
            MockHttpServletResponse res = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();

            filter.doFilter(req, res, chain);
            assertThat(res.getStatus()).as("Expected 404 on admin port for %s", blocked).isEqualTo(404);
            assertThat(chain.getRequest()).isNull();
        }
    }

    @Test
    void rejectsRequestsOnUnconfiguredPortWhenEnabled() throws Exception {
        AppSecurityProperties props = enabledIsolation(8080, 8443);
        PortIsolationFilter filter = new PortIsolationFilter(props);

        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/console/");
        req.setLocalPort(7777);
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(req, res, chain);
        assertThat(res.getStatus()).isEqualTo(404);
        assertThat(chain.getRequest()).isNull();
    }

    private static AppSecurityProperties enabledIsolation(int ocspPort, int adminPort) {
        AppSecurityProperties props = new AppSecurityProperties();
        props.getPortIsolation().setEnabled(true);
        props.getPortIsolation().setOcspPort(ocspPort);
        props.getPortIsolation().setAdminPort(adminPort);
        return props;
    }
}

