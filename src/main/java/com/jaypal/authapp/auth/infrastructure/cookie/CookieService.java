package com.jaypal.authapp.auth.infrastructure.cookie;

import com.jaypal.authapp.config.JwtCookieProperties;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.net.IDN;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Set;

@Slf4j
@Service
@Getter
public class CookieService {

    private static final String COOKIE_PATH = "/";
    private static final String NO_CACHE_HEADER_VALUE =
            "no-store, no-cache, must-revalidate, max-age=0";
    private static final Set<String> VALID_SAMESITE_VALUES =
            Set.of("Strict", "Lax", "None");

    private final String refreshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieDomain;
    private final String cookieSameSite;

    public CookieService(JwtCookieProperties properties) {
        Objects.requireNonNull(properties, "JwtCookieProperties cannot be null");

        this.refreshTokenCookieName = properties.getRefreshTokenCookieName();
        this.cookieHttpOnly = properties.isCookieHttpOnly();
        this.cookieSecure = properties.isCookieSecure();
        this.cookieDomain = properties.getCookieDomain();
        this.cookieSameSite = properties.getCookieSameSite();
    }

    @PostConstruct
    public void validateConfiguration() {
        if (refreshTokenCookieName == null || refreshTokenCookieName.isBlank()) {
            throw new IllegalStateException("Cookie name cannot be null or empty");
        }

        if (!VALID_SAMESITE_VALUES.contains(cookieSameSite)) {
            throw new IllegalStateException(
                    String.format("Invalid SameSite value '%s'. Must be one of: %s",
                            cookieSameSite, VALID_SAMESITE_VALUES)
            );
        }

        if ("None".equalsIgnoreCase(cookieSameSite) && !cookieSecure) {
            throw new IllegalStateException(
                    "Cookie security violation: SameSite=None requires Secure=true"
            );
        }

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            validateDomain(cookieDomain);
        }

        if (!cookieHttpOnly) {
            log.warn("SECURITY WARNING: HttpOnly is disabled. Cookies are vulnerable to XSS attacks!");
        }

        if (!cookieSecure) {
            log.warn("SECURITY WARNING: Secure flag is disabled. Use only in local development!");
        }

        log.info("Cookie configuration validated [name={}, httpOnly={}, secure={}, sameSite={}, domain={}]",
                refreshTokenCookieName,
                cookieHttpOnly,
                cookieSecure,
                cookieSameSite,
                cookieDomain != null && !cookieDomain.isBlank() ? cookieDomain : "<not set>"
        );
    }

    public void attachRefreshCookie(
            HttpServletResponse response,
            String token,
            int maxAgeSeconds
    ) {
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null");
        }
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Refresh token must not be blank");
        }
        if (maxAgeSeconds <= 0) {
            throw new IllegalArgumentException("Max age must be positive");
        }

        final String encoded = URLEncoder.encode(token, StandardCharsets.UTF_8);
        final ResponseCookie cookie = buildCookie(encoded, maxAgeSeconds);
        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        addNoStoreHeader(response);

        log.debug("Refresh cookie attached with maxAge: {}s", maxAgeSeconds);
    }

    public void clearRefreshCookie(HttpServletResponse response) {
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null");
        }

        final ResponseCookie cookie = buildCookie("", 0);

        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        log.debug("Refresh cookie cleared");
    }

    public void addNoStoreHeader(HttpServletResponse response) {
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null");
        }
        response.setHeader(HttpHeaders.CACHE_CONTROL, NO_CACHE_HEADER_VALUE);
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        response.setHeader(HttpHeaders.EXPIRES, "0");
    }

    private ResponseCookie buildCookie(String value, int maxAgeSeconds) {
        final ResponseCookie.ResponseCookieBuilder builder = ResponseCookie
                .from(refreshTokenCookieName, value)
                .httpOnly(cookieHttpOnly)
                .secure(cookieSecure)
                .path(COOKIE_PATH)
                .maxAge(maxAgeSeconds)
                .sameSite(cookieSameSite);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            builder.domain(cookieDomain);
        }

        return builder.build();
    }

    private void validateDomain(String domain) {
        if (domain.startsWith(".") || domain.endsWith(".")) {
            throw new IllegalStateException(
                    "Invalid cookie domain: cannot start or end with dot: " + domain
            );
        }

        if (domain.contains("..")) {
            throw new IllegalStateException(
                    "Invalid cookie domain: contains consecutive dots: " + domain
            );
        }

        try {
            IDN.toASCII(domain);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException(
                    "Invalid cookie domain format: " + domain, ex
            );
        }

        if (domain.equals("localhost") && cookieSecure) {
            log.warn("Cookie domain 'localhost' with Secure=true may not work in all browsers");
        }
    }
}

/*
CHANGELOG:
1. Added @PostConstruct validation to fail fast on startup
2. Added validation for SameSite values (must be Strict/Lax/None)
3. Added domain validation (no leading/trailing dots, no consecutive dots, valid IDN)
4. Added validation for cookie name (not null or blank)
5. Added security warnings for disabled HttpOnly and Secure flags
6. Added validation for JWT (not null or blank)
7. Added validation for maxAgeSeconds (must be positive)
8. Extracted cookie building to private method to reduce duplication
9. Added Expires header to no-store directive for better browser compatibility
10. Added comprehensive logging for cookie operations
11. Added localhost + Secure flag warning
12. Used Set.of() for valid SameSite values instead of hardcoding
*/