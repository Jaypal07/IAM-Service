package com.jaypal.authapp.auth.infrastructure.cookie;

import com.jaypal.authapp.config.JwtCookieProperties;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

@Service
@Getter
@Slf4j
public class CookieService {

    private static final String COOKIE_PATH = "/";
    private static final String NO_CACHE_HEADER_VALUE =
            "no-store, no-cache, must-revalidate, max-age=0";

    private final String refreshTokenCookieName;
    private final boolean cookieHttpOnly;
    private final boolean cookieSecure;
    private final String cookieDomain;
    private final String cookieSameSite;

    public CookieService(JwtCookieProperties properties) {
        Objects.requireNonNull(properties, "JwtCookieProperties must not be null");

        if ("None".equalsIgnoreCase(properties.getCookieSameSite())
                && !properties.isCookieSecure()) {
            throw new IllegalStateException(
                    "Invalid cookie configuration: SameSite=None requires Secure=true"
            );
        }

        this.refreshTokenCookieName = properties.getRefreshTokenCookieName();
        this.cookieHttpOnly = properties.isCookieHttpOnly();
        this.cookieSecure = properties.isCookieSecure();
        this.cookieDomain = properties.getCookieDomain();
        this.cookieSameSite = properties.getCookieSameSite();

        log.info(
                "CookieService initialized [name={}, httpOnly={}, secure={}, sameSite={}, domain={}]",
                refreshTokenCookieName,
                cookieHttpOnly,
                cookieSecure,
                cookieSameSite,
                (cookieDomain == null || cookieDomain.isBlank()) ? "<default>" : cookieDomain
        );
    }

    // ---------- SET / OVERWRITE ----------

    public void attachRefreshCookie(
            HttpServletResponse response,
            String jwt,
            int maxAgeSeconds
    ) {
        Objects.requireNonNull(response, "HttpServletResponse must not be null");
        Objects.requireNonNull(jwt, "JWT must not be null");

        String encoded =
                URLEncoder.encode(jwt, StandardCharsets.UTF_8);

        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(refreshTokenCookieName, encoded)
                        .httpOnly(cookieHttpOnly)
                        .secure(cookieSecure)
                        .path(COOKIE_PATH)
                        .maxAge(maxAgeSeconds)
                        .sameSite(cookieSameSite);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            builder.domain(cookieDomain);
        }

        response.setHeader(
                HttpHeaders.SET_COOKIE,
                builder.build().toString()
        );
    }

    // ---------- CLEAR ----------

    public void clearRefreshCookie(HttpServletResponse response) {
        Objects.requireNonNull(response, "HttpServletResponse must not be null");

        ResponseCookie.ResponseCookieBuilder builder =
                ResponseCookie.from(refreshTokenCookieName, "")
                        .httpOnly(cookieHttpOnly)
                        .secure(cookieSecure)
                        .path(COOKIE_PATH)
                        .maxAge(0)
                        .sameSite(cookieSameSite);

        if (cookieDomain != null && !cookieDomain.isBlank()) {
            builder.domain(cookieDomain);
        }

        response.setHeader(
                HttpHeaders.SET_COOKIE,
                builder.build().toString()
        );
    }

    public void addNoStoreHeader(HttpServletResponse response) {
        Objects.requireNonNull(response, "HttpServletResponse must not be null");

        response.setHeader(HttpHeaders.CACHE_CONTROL, NO_CACHE_HEADER_VALUE);
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
    }
}
