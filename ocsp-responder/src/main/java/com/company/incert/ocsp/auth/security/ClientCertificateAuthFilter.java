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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Native Tomcat mTLS X.509 client-certificate authentication filter.
 * Active only when {@code security.tls.client-cert-auth-enabled=true}.
 * Reads the client certificate exclusively from the native TLS servlet attribute
 * ({@code jakarta.servlet.request.X509Certificate}) verified by {@code HotReloadableTrustManager}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ClientCertificateAuthFilter extends OncePerRequestFilter {

    private static final String X509_CERT_ATTR = "jakarta.servlet.request.X509Certificate";

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
                        log.debug("[mTLS] Authenticated user='{}' via native TLS client certificate", principal.username());
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
        return Optional.empty();
    }
}
