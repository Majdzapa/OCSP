package lu.incert.ocsp.auth.security;

import lu.incert.ocsp.auth.config.AppAuthProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Authenticates {@code Authorization: Bearer <jwt>} requests in {@code SELF_MANAGEMENT} mode
 * using {@link LocalJwtTokenService}.
 */
@Component
@RequiredArgsConstructor
public class LocalBearerTokenAuthFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AppAuthProperties authProperties;
    private final LocalJwtTokenService tokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!authProperties.resolvedMode().isKeycloak()
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String header = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (header != null && header.startsWith(BEARER_PREFIX)) {
                String token = header.substring(BEARER_PREFIX.length()).trim();
                tokenService.parseAndValidate(token).ifPresent(principal -> {
                    var authorities = principal.roles().stream()
                            .map(SimpleGrantedAuthority::new)
                            .toList();
                    var auth = new UsernamePasswordAuthenticationToken(principal, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                });
            }
        }
        filterChain.doFilter(request, response);
    }
}

