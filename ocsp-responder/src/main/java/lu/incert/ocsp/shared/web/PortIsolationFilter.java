package lu.incert.ocsp.shared.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lu.incert.ocsp.shared.config.AppSecurityProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * L4 Data Plane / Control Plane port isolation filter for production PKI deployments.
 * <p>
 * Activated when {@code security.port-isolation.enabled=true}:
 * <ul>
 *   <li><b>Public OCSP Data Plane</b> ({@code security.port-isolation.ocsp-port}, default 8080):
 *       permits ONLY RFC 6960 {@code /ocsp} endpoints and Pattern A {@code /ocsp/health}.
 *       All admin console, admin API, docs, and actuator requests return {@code 404 Not Found}.</li>
 *   <li><b>Dedicated Management Control Plane</b> ({@code security.port-isolation.admin-port}, e.g. 8443 HTTPS/mTLS or 9090):
 *       permits {@code /console/**}, {@code /api/**}, {@code /docs/**}, {@code /actuator/**}, and {@code /ocsp/health}.
 *       Rejects RFC 6960 signing requests ({@code /ocsp}, {@code /ocsp/{base64}}) with {@code 404 Not Found}.</li>
 * </ul>
 * When {@code security.port-isolation.enabled=false} (default for {@code dev}/{@code local}), all endpoints remain
 * reachable on the single default port for developer convenience.
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
@RequiredArgsConstructor
public class PortIsolationFilter extends OncePerRequestFilter {

    private final AppSecurityProperties securityProperties;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        AppSecurityProperties.PortIsolation isolation = securityProperties.getPortIsolation();
        if (isolation == null || !isolation.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        int localPort = request.getLocalPort();
        String path = extractNormalizedPath(request);

        if (localPort == isolation.getOcspPort()) {
            if (!isPublicOcspPath(path)) {
                log.debug("Port isolation blocked non-OCSP path '{}' on public OCSP port {}", path, localPort);
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }
        } else if (localPort == isolation.getAdminPort()) {
            if (isOcspSigningPath(path)) {
                log.debug("Port isolation blocked RFC 6960 signing path '{}' on management port {}", path, localPort);
                response.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }
        } else {
            log.warn("Port isolation rejected request to '{}' on unconfigured port {}", path, localPort);
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private static String extractNormalizedPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)) {
            uri = uri.substring(contextPath.length());
        }
        return uri.isEmpty() ? "/" : uri;
    }

    private static boolean isPublicOcspPath(String path) {
        return "/ocsp".equals(path) || path.startsWith("/ocsp/");
    }

    private static boolean isOcspSigningPath(String path) {
        if ("/ocsp/health".equals(path)) {
            return false;
        }
        return "/ocsp".equals(path) || path.startsWith("/ocsp/");
    }
}
