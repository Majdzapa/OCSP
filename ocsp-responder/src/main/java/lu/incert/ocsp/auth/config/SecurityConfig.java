package lu.incert.ocsp.auth.config;

import lu.incert.ocsp.auth.security.ClientCertificateAuthFilter;
import lu.incert.ocsp.auth.security.LocalBearerTokenAuthFilter;
import lu.incert.ocsp.auth.security.OcspPermissionEvaluator;
import lu.incert.ocsp.shared.config.AppSecurityProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Security &amp; RBAC configuration supporting {@code app.auth.mode = SELF_MANAGEMENT | KEYCLOAK}
 * (without cross-system user synchronization) and fine-grained {@code hasPermission(...)} method security.
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
    private final ClientCertificateAuthFilter clientCertificateAuthFilter;
    private final LocalBearerTokenAuthFilter localBearerTokenAuthFilter;
    private final OcspPermissionEvaluator permissionEvaluator;

    public AuthenticationMode getAuthenticationMode() {
        return authProperties.resolvedMode();
    }

    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler() {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        return handler;
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

    @Bean
    @Order(2)
    public SecurityFilterChain authBoundaryFilterChain(HttpSecurity http) throws Exception {
        AuthenticationMode mode = getAuthenticationMode();
        http
            .securityMatcher("/api/v1/auth/**")
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
                .requestMatchers("/api/v1/admin/**").authenticated()
                .anyRequest().authenticated()
            );

        applyAuthMechanisms(http, mode);
        return http.build();
    }

    private void applyAuthMechanisms(HttpSecurity http, AuthenticationMode mode) throws Exception {
        http.httpBasic(AbstractHttpConfigurer::disable);
        http.addFilterBefore(clientCertificateAuthFilter, UsernamePasswordAuthenticationFilter.class);

        if (mode.isKeycloak()) {
            log.info("Activating KEYCLOAK stateless OAuth2 Resource Server filter chain");
            http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(new KeycloakJwtAuthenticationConverter())
                )
            );
        } else {
            log.info("Activating SELF_MANAGEMENT Bearer JWT filter chain");
            http.addFilterBefore(localBearerTokenAuthFilter, UsernamePasswordAuthenticationFilter.class);
        }
    }
}
