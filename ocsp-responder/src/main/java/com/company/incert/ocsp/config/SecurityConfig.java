package com.company.incert.ocsp.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Security & RBAC configuration supporting dual authentication modes:
 * <ul>
 *   <li><b>SELF_MANAGED</b>: Username and password authentication backed by {@code users} / {@code roles} tables.</li>
 *   <li><b>KEYCLOAK</b>: OAuth2 / OpenID Connect Resource Server validating Keycloak JWT Bearer tokens.</li>
 * </ul>
 * Roles: {@code ROLE_ADMIN}, {@code ROLE_AGENT}, {@code ROLE_AUDITOR}.
 */
@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AppSecurityProperties securityProperties;
    private final KeycloakProperties keycloakProperties;

    public AuthenticationMode getAuthenticationMode() {
        return securityProperties.authenticationMode();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(securityProperties.getCors().getAllowedOrigins());
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    public JwtDecoder jwtDecoder() {
        String jwkSetUri = keycloakProperties.effectiveJwkSetUri();
        log.info("Initializing NimbusJwtDecoder for Keycloak with JWKS URI: {}", jwkSetUri);
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationMode mode = getAuthenticationMode();
        log.info("Configuring OCSP Responder Security & RBAC with Authentication Mode: {}", mode);

        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                // Allow CORS pre-flight
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // Static web resources & landing page
                .requestMatchers("/", "/index.html", "/login.html", "/favicon.ico", "/static/**").permitAll()
                // OpenAPI / Swagger UI endpoints
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                // RFC 6960 OCSP endpoints MUST be public for relying parties
                .requestMatchers("/ocsp", "/ocsp/**").permitAll()
                // Healthcheck endpoints
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                // Auth check & configuration endpoints (read-only, no secrets)
                .requestMatchers("/api/v1/auth/config", "/api/v1/auth/me").permitAll()
                // Login endpoint is public so credentials can be submitted
                .requestMatchers("/api/v1/auth/login").permitAll()

                // --- RBAC: Admin-only endpoints ---
                .requestMatchers("/api/v1/admin/users/**", "/api/v1/admin/roles/**").hasRole("ADMIN")
                .requestMatchers(HttpMethod.PUT,
                        "/api/v1/admin/signing-certificates/*/activate",
                        "/api/v1/admin/signing-certificates/*/deactivate").hasRole("ADMIN")
                .requestMatchers(HttpMethod.DELETE, "/api/v1/admin/signing-certificates/*").hasRole("ADMIN")

                // --- RBAC: Admin & Agent operational endpoints ---
                .requestMatchers(HttpMethod.POST,
                        "/api/v1/admin/signing-certificates/csr",
                        "/api/v1/admin/signing-certificates/*/renew-request",
                        "/api/v1/admin/signing-certificates",
                        "/api/v1/admin/signing-certificates/validity/check",
                        "/api/v1/admin/reconciliation/replay").hasAnyRole("ADMIN", "AGENT")

                // --- RBAC: Read-only audit & dashboard endpoints (Admin, Agent, Auditor) ---
                .requestMatchers(HttpMethod.GET, "/api/v1/admin/**").hasAnyRole("ADMIN", "AGENT", "AUDITOR")

                // Catch-all for any other /api/v1/admin/** mutation requires ADMIN
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            );

        // HTTP Basic Auth is active in both modes (standard auth in SELF_MANAGED, break-glass fallback in KEYCLOAK)
        http.httpBasic(Customizer.withDefaults());

        if (mode.isKeycloak()) {
            log.info("Activating KEYCLOAK OAuth2 Resource Server filter chain");
            http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())
                )
            );
        }

        return http.build();
    }
}
