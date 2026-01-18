package com.jaypal.authapp.infrastructure.utils;

import com.jaypal.authapp.config.properties.JwtCookieProperties;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.Set;

@Slf4j
@Service
@Getter
public class CookieService {

    private static final String PATH = "/";
    private static final String NO_CACHE =
            "no-store, no-cache, must-revalidate, max-age=0";

    private static final Set<String> VALID_SAMESITE =
            Set.of("Strict", "Lax", "None");

    private final String refreshTokenCookieName;
    private final boolean httpOnly;
    private final boolean secure;
    private final String domain;
    private final String sameSite;

    public CookieService(JwtCookieProperties props) {
        Objects.requireNonNull(props);
        this.refreshTokenCookieName = props.getRefreshTokenCookieName();
        this.httpOnly = props.isCookieHttpOnly();
        this.secure = props.isCookieSecure();
        this.domain = props.getCookieDomain();
        this.sameSite = props.getCookieSameSite();
    }

    @PostConstruct
    void validate() {
        if (!VALID_SAMESITE.contains(sameSite)) {
            throw new IllegalStateException("Invalid SameSite: " + sameSite);
        }
        if ("None".equals(sameSite) && !secure) {
            throw new IllegalStateException("SameSite=None requires Secure");
        }
    }

    public void attachRefreshCookie(HttpServletResponse response, String token, int maxAge) {
        ResponseCookie cookie = build(token, maxAge);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
        addNoStoreHeader(response);
    }

    public void clearRefreshCookie(HttpServletResponse response) {
        ResponseCookie cookie = build("", 0);
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void addNoStoreHeader(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, NO_CACHE);
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        response.setHeader(HttpHeaders.EXPIRES, "0");
    }

    private ResponseCookie build(String value, int maxAge) {
        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie
                .from(refreshTokenCookieName, value)
                .httpOnly(httpOnly)
                .secure(secure)
                .path(PATH)
                .sameSite(sameSite)
                .maxAge(maxAge);

        if (domain != null && !domain.isBlank()) {
            builder.domain(domain);
        }

        return builder.build();
    }
}
