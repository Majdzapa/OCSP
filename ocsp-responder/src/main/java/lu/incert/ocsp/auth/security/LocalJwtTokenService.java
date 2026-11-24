package lu.incert.ocsp.auth.security;

import lu.incert.ocsp.auth.config.AppAuthProperties;
import lu.incert.ocsp.auth.entity.AuthSource;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Issues and verifies HS256 Bearer JWTs for {@code app.auth.mode=SELF_MANAGEMENT}.
 */
@Slf4j
@Service
public class LocalJwtTokenService {

    private final AppAuthProperties authProperties;

    public LocalJwtTokenService(AppAuthProperties authProperties) {
        this.authProperties = authProperties;
    }

    public String issueToken(InternalPrincipal principal) {
        try {
            byte[] keyBytes = signingKeyBytes();
            Instant now = Instant.now();
            Duration ttl = effectiveExpiration();
            Instant expiresAt = now.plus(ttl);

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(effectiveIssuer())
                    .subject(principal.userId() != null ? principal.userId() : principal.username())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiresAt))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("preferred_username", principal.username())
                    .claim("email", principal.email())
                    .claim("name", principal.fullName())
                    .claim("tenant_id", principal.tenantId())
                    .claim("roles", principal.roles().stream().sorted().toList())
                    .build();

            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
            signedJWT.sign(new MACSigner(keyBytes));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign local Bearer JWT: " + e.getMessage(), e);
        }
    }

    public Optional<InternalPrincipal> parseAndValidate(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            SignedJWT signedJWT = SignedJWT.parse(token.trim());
            if (!JWSAlgorithm.HS256.equals(signedJWT.getHeader().getAlgorithm())) {
                return Optional.empty();
            }
            if (!signedJWT.verify(new MACVerifier(signingKeyBytes()))) {
                return Optional.empty();
            }
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Date exp = claims.getExpirationTime();
            if (exp == null || Instant.now().isAfter(exp.toInstant())) {
                return Optional.empty();
            }

            String username = claims.getStringClaim("preferred_username");
            if (username == null || username.isBlank()) {
                username = claims.getSubject();
            }
            List<String> roleList = claims.getStringListClaim("roles");
            Set<String> roles = roleList != null
                    ? roleList.stream().filter(Objects::nonNull).collect(Collectors.toSet())
                    : Set.of();

            return Optional.of(new InternalPrincipal(
                    claims.getSubject(),
                    username,
                    claims.getStringClaim("email"),
                    claims.getStringClaim("name"),
                    claims.getStringClaim("tenant_id") != null ? claims.getStringClaim("tenant_id") : "default",
                    AuthSource.LOCAL,
                    roles
            ));
        } catch (Exception e) {
            log.debug("Rejected invalid local Bearer JWT: {}", e.getMessage());
            return Optional.empty();
        }
    }

    public long expiresInSeconds() {
        return effectiveExpiration().toSeconds();
    }

    private Duration effectiveExpiration() {
        Duration d = authProperties.getJwt().getExpiration();
        return (d != null && !d.isNegative() && !d.isZero()) ? d : Duration.ofHours(8);
    }

    private String effectiveIssuer() {
        String iss = authProperties.getJwt().getIssuer();
        return (iss != null && !iss.isBlank()) ? iss : "incert-ocsp";
    }

    private byte[] signingKeyBytes() {
        String rawSecret = authProperties.getJwt().getSecret();
        if (rawSecret == null || rawSecret.isBlank()) {
            throw new IllegalStateException("app.auth.jwt.secret must be configured for SELF_MANAGEMENT Bearer tokens");
        }
        try {
            // Derive a fixed 32-byte (256-bit) HMAC key via SHA-256 so HS256 always has >= 256-bit key material
            return MessageDigest.getInstance("SHA-256").digest(rawSecret.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to derive HS256 signing key", e);
        }
    }
}

