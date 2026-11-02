package com.company.ocsp.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * Spring Authorization Server configuration.
 *
 * <h2>Registered clients</h2>
 * <table border="1">
 *   <tr><th>Client ID</th><th>Secret</th><th>Scopes</th><th>Roles in token</th></tr>
 *   <tr>
 *     <td>ocsp-console</td><td>secret</td>
 *     <td>ocsp.admin</td>
 *     <td>OCSP_ADMIN, OCSP_OPERATOR</td>
 *   </tr>
 *   <tr>
 *     <td>ocsp-operator</td><td>secret</td>
 *     <td>ocsp.read</td>
 *     <td>OCSP_OPERATOR</td>
 *   </tr>
 * </table>
 *
 * <h2>Get a token</h2>
 * <pre>
 * # Admin token (all permissions)
 * curl -s -X POST http://localhost:9000/oauth2/token \
 *   -u "ocsp-console:secret" \
 *   -d "grant_type=client_credentials&amp;scope=ocsp.admin" | jq -r .access_token
 *
 * # Operator token (read-only)
 * curl -s -X POST http://localhost:9000/oauth2/token \
 *   -u "ocsp-operator:secret" \
 *   -d "grant_type=client_credentials&amp;scope=ocsp.read" | jq -r .access_token
 * </pre>
 */
@Slf4j
@Configuration
public class AuthorizationServerConfig {

    // =========================================================================
    // 1. Authorization Server security filter chain
    // =========================================================================

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());   // Enable OIDC 1.0 (/.well-known/openid-configuration)
        return http.build();
    }

    // =========================================================================
    // 2. Registered clients (in-memory, dev only)
    // =========================================================================

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Admin client — gets OCSP_ADMIN + OCSP_OPERATOR roles
        RegisteredClient adminClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("ocsp-console")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("ocsp.admin")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(8))
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        // Operator client — gets only OCSP_OPERATOR role
        RegisteredClient operatorClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("ocsp-operator")
                .clientSecret("{noop}operator-secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("ocsp.read")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(8))
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        log.info("Registered OAuth2 clients: ocsp-console (admin), ocsp-operator (read)");
        return new InMemoryRegisteredClientRepository(adminClient, operatorClient);
    }

    // =========================================================================
    // 3. JWT token customizer — injects 'roles' claim based on scope
    //    SecurityConfig in ocsp-admin-api reads this 'roles' claim.
    // =========================================================================

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                String clientId = context.getRegisteredClient().getClientId();
                List<String> roles = switch (clientId) {
                    case "ocsp-console"  -> List.of("OCSP_ADMIN", "OCSP_OPERATOR");
                    case "ocsp-operator" -> List.of("OCSP_OPERATOR");
                    default              -> List.of();
                };
                context.getClaims().claim("roles", roles);
                log.debug("JWT customized: clientId={} roles={}", clientId, roles);
            }
        };
    }

    // =========================================================================
    // 4. JWK source — RSA key pair for signing JWTs (generated on startup)
    // =========================================================================

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();

        log.info("Generated RSA-2048 key pair for JWT signing");
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // =========================================================================
    // 5. Authorization Server settings
    // =========================================================================

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .build();
    }
}
