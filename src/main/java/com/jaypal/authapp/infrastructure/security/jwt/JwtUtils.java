package com.jaypal.authapp.infrastructure.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public final class JwtUtils {

    private static final long CLOCK_SKEW_SECONDS = 30L;

    private JwtUtils() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    public static SecretKey createKey(String secret) {
        Objects.requireNonNull(secret, "Secret cannot be null");

        if (secret.isBlank()) {
            throw new IllegalArgumentException("Secret cannot be empty");
        }

        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public static String buildAccessToken(
            SecretKey key,
            String issuer,
            UUID subjectId,
            Map<String, Object> claims,
            long ttlSeconds
    ) {
        Objects.requireNonNull(key, "Secret key cannot be null");
        Objects.requireNonNull(issuer, "Issuer cannot be null");
        Objects.requireNonNull(subjectId, "Subject ID cannot be null");
        Objects.requireNonNull(claims, "Claims cannot be null");

        if (issuer.isBlank()) {
            throw new IllegalArgumentException("Issuer cannot be empty");
        }

        if (ttlSeconds <= 0) {
            throw new IllegalArgumentException("TTL must be positive");
        }

        final Instant now = Instant.now();
        final Instant expiration = now.plusSeconds(ttlSeconds);

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(subjectId.toString())
                .setIssuer(issuer)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiration))
                .addClaims(claims)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public static Jws<Claims> parse(
            SecretKey key,
            String expectedIssuer,
            String token
    ) {
        Objects.requireNonNull(key, "Secret key cannot be null");
        Objects.requireNonNull(expectedIssuer, "Expected issuer cannot be null");
        Objects.requireNonNull(token, "Token cannot be null");

        if (expectedIssuer.isBlank()) {
            throw new IllegalArgumentException("Expected issuer cannot be empty");
        }

        if (token.isBlank()) {
            throw new IllegalArgumentException("Token cannot be empty");
        }

        return Jwts.parserBuilder()
                .setSigningKey(key)
                .requireIssuer(expectedIssuer)
                .setAllowedClockSkewSeconds(CLOCK_SKEW_SECONDS)
                .build()
                .parseClaimsJws(token);
    }
}

/*
CHANGELOG:
1. Added private constructor that throws to prevent instantiation
2. Added null checks for all parameters
3. Added validation for empty strings
4. Added TTL validation (must be positive)
5. Added clock skew tolerance (30 seconds) to prevent timing issues
6. Extracted clock skew as constant
7. Made validation messages more descriptive
8. Used Objects.requireNonNull for consistent null checking
9. Made Instant variables final for immutability
*/