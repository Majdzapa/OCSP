package com.company.incert.ocsp.auth.security;

import com.company.incert.ocsp.auth.service.UserCertificateService;
import com.company.incert.ocsp.shared.config.AppSecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Optional mTLS X.509 client-certificate authentication filter.
 * Active only when {@code security.tls.client-cert-auth-enabled=true}.
 * Extracts the presented client certificate from either the servlet attribute
 * ({@code jakarta.servlet.request.X509Certificate}) or the reverse-proxy header
 * ({@code X-Client-Cert}, URL-encoded PEM from Nginx {@code $ssl_client_escaped_cert}),
 * verifies it against the hot-reloaded Trusted CA store, and resolves {@link InternalPrincipal}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ClientCertificateAuthFilter extends OncePerRequestFilter {

    private static final String X509_CERT_ATTR = "jakarta.servlet.request.X509Certificate";
    private static final String CLIENT_CERT_HEADER = "X-Client-Cert";

    private final AppSecurityProperties securityProperties;
    private final UserCertificateService userCertificateService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (securityProperties.getTls().isClientCertAuthEnabled()
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            extractClientCertificate(request)
                    .flatMap(userCertificateService::authenticateByClientCertificate)
                    .ifPresent(principal -> {
                        var authorities = principal.roles().stream()
                                .map(SimpleGrantedAuthority::new)
                                .toList();
                        var auth = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                        SecurityContextHolder.getContext().setAuthentication(auth);
                        log.debug("[mTLS] Authenticated user='{}' via client certificate", principal.username());
                    });
        }
        filterChain.doFilter(request, response);
    }

    public static Optional<X509Certificate> extractClientCertificate(HttpServletRequest request) {
        if (request == null) {
            return Optional.empty();
        }
        Object attr = request.getAttribute(X509_CERT_ATTR);
        if (attr instanceof X509Certificate[] certs && certs.length > 0 && certs[0] != null) {
            return Optional.of(certs[0]);
        }
        String headerVal = request.getHeader(CLIENT_CERT_HEADER);
        if (headerVal != null && !headerVal.isBlank()) {
            try {
                String pem = URLDecoder.decode(headerVal.trim(), StandardCharsets.UTF_8);
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) factory.generateCertificate(
                        new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
                return Optional.of(cert);
            } catch (Exception e) {
                log.debug("Failed to parse X-Client-Cert header: {}", e.getMessage());
            }
        }
        return Optional.empty();
    }
}
