package com.jaypal.authapp.config.properties;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "security.jwt")
public class JwtCookieProperties {

    private String secret;
    private String issuer;
    private long accessTtlSeconds;
    private long refreshTtlSeconds;
    private String refreshTokenCookieName;
    private boolean cookieSecure;
    private boolean cookieHttpOnly;
    private String cookieSameSite;
    private String cookieDomain;

    @PostConstruct
    public void validate() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("JWT secret is required");
        }

        if (secret.length() < 64) {
            throw new IllegalStateException(
                    String.format("JWT secret must be at least 64 characters (current: %d)", secret.length()));
        }

        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException("JWT issuer is required");
        }

        if (accessTtlSeconds <= 0) {
            throw new IllegalStateException("Access token TTL must be positive");
        }

        if (refreshTtlSeconds <= 0) {
            throw new IllegalStateException("Refresh token TTL must be positive");
        }

        if (refreshTtlSeconds < accessTtlSeconds) {
            throw new IllegalStateException(
                    "Refresh token TTL must be >= access token TTL");
        }

        if (refreshTokenCookieName == null || refreshTokenCookieName.isBlank()) {
            throw new IllegalStateException("Refresh token cookie name is required");
        }

        if (cookieSameSite == null || cookieSameSite.isBlank()) {
            throw new IllegalStateException("Cookie SameSite policy is required");
        }

        if (!"Strict".equals(cookieSameSite) &&
                !"Lax".equals(cookieSameSite) &&
                !"None".equals(cookieSameSite)) {
            throw new IllegalStateException(
                    "Cookie SameSite must be Strict, Lax, or None (got: " + cookieSameSite + ")");
        }

        if ("None".equals(cookieSameSite) && !cookieSecure) {
            throw new IllegalStateException(
                    "Cookie SameSite=None requires Secure=true");
        }
    }
}

/*
CHANGELOG:
1. Added @PostConstruct validation to both properties classes
2. Added URL format validation for frontend URLs
3. Added comprehensive JWT configuration validation
4. Made baseUrl required, redirects optional
5. Validated JWT secret length (min 64 chars)
6. Validated TTL values (positive, refresh >= access)
7. Validated SameSite values (Strict/Lax/None)
8. Validated SameSite=None requires Secure=true
9. Made all error messages descriptive with actual values
10. Used @Component + @ConfigurationProperties pattern
*/