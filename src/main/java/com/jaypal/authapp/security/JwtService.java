package com.jaypal.authapp.security;

import com.jaypal.authapp.entity.Role;
import com.jaypal.authapp.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Getter
public class JwtService {

    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_TYPE = "typ";
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    private final SecretKey secretKey;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer) {

        validateSecret(secret);
        this.secretKey = JwtUtils.createKey(secret);
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    // -------------------------------------------------------------------------
    // Token Generation
    // -------------------------------------------------------------------------

    public String generateAccessToken(User user) {

        Map<String, Object> claims = new HashMap<>();

        claims.put(CLAIM_TYPE, TYPE_ACCESS);
        claims.put(CLAIM_ROLES, extractRoleNames(user));

        if (user.getEmail() != null) {
            claims.put(CLAIM_EMAIL, user.getEmail());
        }

        return JwtUtils.buildToken(
                secretKey,
                issuer,
                user.getId(),
                claims,
                accessTtlSeconds
        );
    }

    public String generateRefreshToken(User user, String jti) {

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, TYPE_REFRESH);

        return JwtUtils.buildRefreshToken(
                secretKey,
                issuer,
                user.getId(),
                claims,
                refreshTtlSeconds,
                jti
        );
    }


    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    public boolean isAccessToken(String token) {
        return TYPE_ACCESS.equals(JwtUtils.getClaim(secretKey, token, CLAIM_TYPE));
    }

    public boolean isRefreshToken(String token) {
        return TYPE_REFRESH.equals(JwtUtils.getClaim(secretKey, token, CLAIM_TYPE));
    }

    public UUID getUserId(String token) {
        return JwtUtils.getSubjectId(secretKey, token);
    }

    public String getJti(String token) {
        return JwtUtils.getJti(secretKey, token);
    }

    public Jws<Claims> parse(String token) {
        return JwtUtils.parse(secretKey, token);
    }

    public List<String> getRoles(String token) {
        Claims c = parse(token).getBody();
        return (List<String>) c.get("roles");
    }

    public String getEmail(String token) {
        Claims c = parse(token).getBody();
        return (String) c.get("email");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private List<String> extractRoleNames(User user) {
        if (user.getRoles() == null) return List.of();
        return user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toList());
    }

    private void validateSecret(String secret) {
        if (secret == null || secret.length() < 64) {
            throw new IllegalArgumentException("JWT secret must be at least 64 characters long.");
        }
    }

}
