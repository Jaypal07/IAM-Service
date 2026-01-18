package com.jaypal.authapp.infrastructure.security.jwt;

import com.jaypal.authapp.domain.user.entity.PermissionType;
import com.jaypal.authapp.domain.user.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@Getter
public class JwtService {

    private static final int MINIMUM_SECRET_LENGTH = 64;
    private static final String CLAIM_TYPE = "typ";
    private static final String CLAIM_EMAIL = "email";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_PERMS = "perms";
    private static final String CLAIM_PV = "pv";

    private final String rawSecret;
    private final long accessTtlSeconds;
    private final long refreshTtlSeconds;
    private final String issuer;

    private SecretKey secretKey;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.access-ttl-seconds}") long accessTtlSeconds,
            @Value("${security.jwt.refresh-ttl-seconds}") long refreshTtlSeconds,
            @Value("${security.jwt.issuer}") String issuer
    ) {
        this.rawSecret = secret;
        this.accessTtlSeconds = accessTtlSeconds;
        this.refreshTtlSeconds = refreshTtlSeconds;
        this.issuer = issuer;
    }

    @PostConstruct
    public void init() {
        validateConfiguration();
        this.secretKey = JwtUtils.createKey(rawSecret);
        log.info("JWT Service initialized - Access TTL: {}s, Refresh TTL: {}s, Issuer: {}",
                accessTtlSeconds, refreshTtlSeconds, issuer);
    }

    private void validateConfiguration() {
        if (rawSecret == null || rawSecret.isBlank()) {
            throw new IllegalStateException("JWT secret cannot be null or empty");
        }

        if (rawSecret.length() < MINIMUM_SECRET_LENGTH) {
            throw new IllegalStateException(
                    String.format("JWT secret must be at least %d characters. Current length: %d",
                            MINIMUM_SECRET_LENGTH, rawSecret.length())
            );
        }

        if (accessTtlSeconds <= 0) {
            throw new IllegalStateException("JWT access TTL must be positive");
        }

        if (refreshTtlSeconds <= 0) {
            throw new IllegalStateException("JWT refresh TTL must be positive");
        }

        if (refreshTtlSeconds < accessTtlSeconds) {
            throw new IllegalStateException("Refresh TTL must be greater than or equal to access TTL");
        }

        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException("JWT issuer cannot be null or empty");
        }
    }

    public String generateAccessToken(User user, Set<PermissionType> permissions) {
        Objects.requireNonNull(user, "User cannot be null");
        Objects.requireNonNull(user.getId(), "User ID cannot be null");
        Objects.requireNonNull(user.getEmail(), "User email cannot be null");
        Objects.requireNonNull(permissions, "Permissions cannot be null");

        final Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_TYPE, TokenType.ACCESS.name().toLowerCase());
        claims.put(CLAIM_EMAIL, user.getEmail());
        claims.put(CLAIM_ROLES, new ArrayList<>(user.getRoles()));
        claims.put(CLAIM_PERMS, permissions.stream()
                .map(Enum::name)
                .collect(Collectors.toList()));
        claims.put(CLAIM_PV, user.getPermissionVersion());

        return JwtUtils.buildAccessToken(
                secretKey,
                issuer,
                user.getId(),
                claims,
                accessTtlSeconds
        );
    }

    public Jws<Claims> parseAccessToken(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        final Jws<Claims> parsed = JwtUtils.parse(secretKey, issuer, token);
        final String type = parsed.getBody().get(CLAIM_TYPE, String.class);

        if (type == null || TokenType.from(type) != TokenType.ACCESS) {
            throw new IllegalArgumentException("Token is not an access token");
        }

        return parsed;
    }

    public UUID extractUserId(Claims claims) {
        Objects.requireNonNull(claims, "Claims cannot be null");
        final String subject = claims.getSubject();

        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("Token subject (user ID) is missing");
        }

        try {
            return UUID.fromString(subject);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid user ID format in token: " + subject, ex);
        }
    }

    public long extractPermissionVersion(Claims claims) {
        Objects.requireNonNull(claims, "Claims cannot be null");
        final Long pv = claims.get(CLAIM_PV, Long.class);

        if (pv == null) {
            throw new IllegalArgumentException("Permission version missing from token");
        }

        return pv;
    }

    public Set<String> extractRoles(Claims claims) {
        Objects.requireNonNull(claims, "Claims cannot be null");
        return extractStringSet(claims, CLAIM_ROLES);
    }

    public Set<String> extractPermissions(Claims claims) {
        Objects.requireNonNull(claims, "Claims cannot be null");
        return extractStringSet(claims, CLAIM_PERMS);
    }

    public String extractEmail(Claims claims) {
        Objects.requireNonNull(claims, "Claims cannot be null");
        final String email = claims.get(CLAIM_EMAIL, String.class);

        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email missing from token");
        }

        return email;
    }

    private Set<String> extractStringSet(Claims claims, String claimKey) {
        final Object raw = claims.get(claimKey);

        if (raw == null) {
            return Collections.emptySet();
        }

        if (!(raw instanceof List<?>)) {
            throw new IllegalStateException("Claim '" + claimKey + "' is not a list");
        }

        final List<?> list = (List<?>) raw;
        return list.stream()
                .filter(Objects::nonNull)
                .map(obj -> {
                    if (!(obj instanceof String)) {
                        throw new IllegalStateException("Claim '" + claimKey + "' contains non-string value");
                    }
                    return (String) obj;
                })
                .collect(Collectors.toUnmodifiableSet());
    }
}