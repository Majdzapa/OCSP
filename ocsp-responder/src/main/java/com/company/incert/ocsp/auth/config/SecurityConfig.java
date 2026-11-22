package com.company.incert.ocsp.auth.config;


import com.company.incert.ocsp.shared.config.AppSecurityProperties;
import com.company.incert.ocsp.auth.security.ClientCertificateAuthFilter;
import com.company.incert.ocsp.auth.service.KeycloakSyncService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Security &amp; RBAC configuration supporting dual authentication modes via {@code app.auth.mode}:
 * <ul>
 *   <li><b>SELF_MANAGEMENT</b>: App DB owns credentials, identity, and app profile.</li>
 *   <li><b>KEYCLOAK</b>: Keycloak owns credentials and identity; App DB holds a read-only replica.</li>
 * </ul>
 */
@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AppAuthProperties authProperties;
    private final AppSecurityProperties securityProperties;
    private final KeycloakProperties keycloakProperties;
    private final KeycloakSyncService keycloakSyncService;
    private final ClientCertificateAuthFilter clientCertificateAuthFilter;

    public AuthenticationMode getAuthenticationMode() {
        return authProperties.resolvedMode();
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

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    public JwtDecoder jwtDecoder() {
        String jwkSetUri = keycloakProperties.effectiveJwkSetUri();
        log.info("Initializing NimbusJwtDecoder for Keycloak with JWKS URI: {}", jwkSetUri);
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    /**
     * Chain 1: Public RFC 6960 OCSP protocol, health probes, and OpenAPI docs (zero auth overhead).
     */
    @Bean
    @Order(1)
    public SecurityFilterChain ocspProtocolFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/ocsp", "/ocsp/**", "/actuator/health", "/actuator/info",
                    "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html")
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    /**
     * Chain 2: Isolated authentication &amp; Keycloak sync webhook boundary.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain authBoundaryFilterChain(HttpSecurity http) throws Exception {
        AuthenticationMode mode = getAuthenticationMode();
        http
            .securityMatcher("/api/v1/auth/**", "/api/v1/internal/keycloak/events")
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().permitAll()
            );
        applyAuthMechanisms(http, mode);
        return http.build();
    }

    /**
     * Chain 3: Protected business &amp; administrative RBAC plane.
     */
    @Bean
    @Order(3)
    public SecurityFilterChain adminAndAppFilterChain(HttpSecurity http) throws Exception {
        AuthenticationMode mode = getAuthenticationMode();
        log.info("Configuring OCSP Responder Security & RBAC with app.auth.mode={}", mode);

        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/", "/index.html", "/login.html", "/favicon.ico", "/static/**").permitAll()

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

                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            );

        applyAuthMechanisms(http, mode);
        return http.build();
    }

    private void applyAuthMechanisms(HttpSecurity http, AuthenticationMode mode) throws Exception {
        http.httpBasic(Customizer.withDefaults());
        http.addFilterBefore(clientCertificateAuthFilter, BasicAuthenticationFilter.class);

        if (mode.isKeycloak()) {
            log.info("Activating KEYCLOAK OAuth2 Resource Server filter chain with JIT provisioning");
            http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter(keycloakSyncService))
                )
            );
        }
    }
}
