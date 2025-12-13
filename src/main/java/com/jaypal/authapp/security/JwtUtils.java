package com.jaypal.authapp.security;

import com.jaypal.authapp.entities.Role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
public final class JwtUtils {

    private JwtUtils() {}

    // Create SecretKey from string
    public static SecretKey createKey(String secret) {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // Build a signed JWT
    public static String buildToken(
            SecretKey key,
            String issuer,
            UUID subjectId,
            Map<String, Object> claims,
            long ttlSeconds
    ) {
        Instant now = Instant.now();

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(subjectId.toString())
                .setIssuer(issuer)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(ttlSeconds)))
                .addClaims(claims)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    // Build a signed JWT
    public static String buildRefreshToken(
            SecretKey key,
            String issuer,
            UUID subjectId,
            Map<String, Object> claims,
            long ttlSeconds,
            String jti
    ) {
        Instant now = Instant.now();

        return Jwts.builder()
                .setId(jti)
                .setSubject(subjectId.toString())
                .setIssuer(issuer)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusSeconds(ttlSeconds)))
                .addClaims(claims)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }


    // Parse & validate
    public static Jws<Claims> parse(SecretKey key, String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
        } catch (ExpiredJwtException e) {
            throw new JwtException("Token expired");
        } catch (JwtException e) {
            throw new JwtException("Invalid JWT token");
        }

    }

    // Extract a claim
    public static Object getClaim(SecretKey key, String token, String claimKey) {
        return parse(key, token).getBody().get(claimKey);
    }

    public static UUID getSubjectId(SecretKey key, String token) {
        return UUID.fromString(parse(key, token).getBody().getSubject());
    }

    public static String getJti(SecretKey key, String token) {
        return parse(key, token).getBody().getId();
    }

}
