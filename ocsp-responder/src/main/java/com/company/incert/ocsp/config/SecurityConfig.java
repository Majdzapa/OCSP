package com.company.incert.ocsp.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Security configuration supporting dual authentication modes:
 * <ul>
 *   <li><b>SELF_MANAGED</b> (default): HTTP Basic Auth (admin / changeme) and API Key (X-API-KEY).</li>
 *   <li><b>KEYCLOCK</b>: OAuth2 / OpenID Connect Resource Server validating Keycloak JWT Bearer tokens.</li>
 * </ul>
 * Configured via {@code security.auth-mode} or {@code auth.mode}.
 */
@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${security.auth-mode:${auth.mode:SELF_MANAGED}}")
    private String authModeStr;

    @Value("${admin.username:admin}")
    private String adminUsername;

    @Value("${admin.password:changeme}")
    private String adminPassword;

    @Value("${admin.api-key:incert-admin-secret-key}")
    private String adminApiKey;

    @Value("${keycloak.jwk-set-uri:${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:http://localhost:8081/realms/incert/protocol/openid-connect/certs}}")
    private String keycloakJwkSetUri;

    public AuthenticationMode getAuthenticationMode() {
        return AuthenticationMode.fromString(authModeStr);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));
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
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails admin = User.builder()
                .username(adminUsername)
                .password(passwordEncoder.encode(adminPassword))
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(admin);
    }

    public JwtDecoder jwtDecoder() {
        log.info("Initializing NimbusJwtDecoder for Keycloak with JWKS URI: {}", keycloakJwkSetUri);
        return NimbusJwtDecoder.withJwkSetUri(keycloakJwkSetUri).build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthenticationMode mode = getAuthenticationMode();
        log.info("Configuring OCSP Responder Security with Authentication Mode: {}", mode);

        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .addFilterBefore(new ApiKeyAuthFilter(adminApiKey), UsernamePasswordAuthenticationFilter.class)
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
                // Auth check & configuration endpoints
                .requestMatchers("/api/v1/auth/**").permitAll()
                // All admin & management endpoints require ROLE_ADMIN
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            );

        // HTTP Basic Auth is active in both modes (standard auth in SELF_MANAGED, break-glass admin fallback in KEYCLOCK)
        http.httpBasic(Customizer.withDefaults());

        if (mode.isKeycloak()) {
            log.info("Activating KEYCLOCK OAuth2 Resource Server filter chain");
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
