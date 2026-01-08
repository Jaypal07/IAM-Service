package com.jaypal.authapp.security.jwt;

import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Getter
@Slf4j
public class JwtService {

    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_PERMS = "perms";
    private static final String CLAIM_TYPE = "typ";
    private static final String CLAIM_PV = "pv";

    private final SecretKey secretKey;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer
    ) {
        validateSecret(secret);
        this.secretKey = JwtUtils.createKey(secret);
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    /* =========================
       TOKEN GENERATION
       ========================= */

    public String generateAccessToken(
            User user,
            Set<PermissionType> permissions
    ) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, TokenType.ACCESS.name().toLowerCase());
        claims.put(CLAIM_ROLES, new ArrayList<>(user.getRoles()));
        claims.put(
                CLAIM_PERMS,
                permissions.stream()
                        .map(Enum::name)
                        .collect(Collectors.toList())
        );

        if (user.getEmail() != null) {
            claims.put(CLAIM_EMAIL, user.getEmail());
        }
        claims.put(CLAIM_PV, user.getPermissionVersion());

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
        claims.put(CLAIM_TYPE, TokenType.REFRESH.name().toLowerCase());

        return JwtUtils.buildRefreshToken(
                secretKey,
                issuer,
                user.getId(),
                claims,
                refreshTtlSeconds,
                jti
        );
    }

    /* =========================
       TOKEN PARSING
       ========================= */

    public Jws<Claims> parse(String token) {
        return JwtUtils.parse(secretKey, issuer, token);
    }

    public boolean isAccessToken(Jws<Claims> parsed) {
        return TokenType.from(parsed.getBody().get(CLAIM_TYPE, String.class))
                == TokenType.ACCESS;
    }

    public boolean isRefreshToken(Jws<Claims> parsed) {
        return TokenType.from(parsed.getBody().get(CLAIM_TYPE, String.class))
                == TokenType.REFRESH;
    }

    /* =========================
       CLAIM EXTRACTION
       ========================= */

    public UUID extractUserId(Claims claims) {
        return UUID.fromString(claims.getSubject());
    }

    public String extractEmail(Claims claims) {
        return claims.get(CLAIM_EMAIL, String.class);
    }

    public Set<String> extractRoles(Claims claims) {
        return extractStringSet(claims, CLAIM_ROLES);
    }

    public Set<String> extractPermissions(Claims claims) {
        return extractStringSet(claims, CLAIM_PERMS);
    }

    public long extractPermissionVersion(Claims claims) {return claims.get(CLAIM_PV, Long.class);}

    private Set<String> extractStringSet(Claims claims, String key) {
        Object raw = claims.get(key);
        if (raw == null) return Set.of();

        if (!(raw instanceof List<?> list)) {
            throw new IllegalStateException("Invalid claim: " + key);
        }

        return list.stream()
                .map(String.class::cast)
                .collect(Collectors.toUnmodifiableSet());
    }

    private void validateSecret(String secret) {
        if (secret == null || secret.length() < 64) {
            throw new IllegalArgumentException(
                    "JWT secret must be at least 64 characters long"
            );
        }
    }
}
