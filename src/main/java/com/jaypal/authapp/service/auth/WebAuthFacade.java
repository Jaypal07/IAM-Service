package com.jaypal.authapp.service.auth;

import com.jaypal.authapp.config.properties.RateLimitProperties;
import com.jaypal.authapp.dto.audit.AuditRequestContext;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitContext;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitExceededException;
import com.jaypal.authapp.infrastructure.ratelimit.RedisRateLimiter;
import com.jaypal.authapp.infrastructure.ratelimit.RequestIpResolver;
import com.jaypal.authapp.dto.auth.AuthLoginResult;
import com.jaypal.authapp.dto.auth.RefreshTokenRequest;
import com.jaypal.authapp.exception.auth.MissingRefreshTokenException;
import com.jaypal.authapp.infrastructure.utils.RefreshTokenExtractor;
import com.jaypal.authapp.infrastructure.utils.CookieService;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.domain.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.domain.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.domain.token.exception.RefreshTokenRevokedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class WebAuthFacade {

    private final AuthService authService;
    private final CookieService cookieService;
    private final RefreshTokenExtractor refreshTokenExtractor;

    private final RedisRateLimiter rateLimiter;
    private final RateLimitProperties rateLimitProperties;

    /* =========================
       LOGIN FLOW
       ========================= */

    public AuthLoginResult login(AuthPrincipal principal, HttpServletResponse response) {
        if (principal == null) {
            log.error("Login aborted. AuthPrincipal is null");
            throw new IllegalArgumentException("AuthPrincipal must not be null");
        }

        log.debug("Login flow started | userId={}", principal.getUserId());

        AuthLoginResult result = authService.login(principal);

        log.debug(
                "Login successful | userId={} refreshExpiresAt={}",
                result.user().id(),
                result.refreshExpiresAtEpochSeconds()
        );

        attachRefreshCookie(response, result);

        log.debug("Login flow completed | userId={}", principal.getUserId());
        return result;
    }

    /* =========================
       REFRESH FLOW
       ========================= */

    public AuthLoginResult refresh(
            HttpServletRequest request,
            HttpServletResponse response,
            RefreshTokenRequest body
    ) {
        final String ip = RequestIpResolver.resolve(request);

        log.debug("Refresh flow started | ip={}", ip);

        try {
            String refreshToken =
                    refreshTokenExtractor.extract(request)
                            .or(() -> Optional.ofNullable(body)
                                    .map(RefreshTokenRequest::refreshToken)
                                    .filter(t -> !t.isBlank())
                                    .map(token -> {
                                        log.debug(
                                                "Refresh token extracted from body | length={} prefix={}",
                                                token.length(),
                                                token.substring(0, Math.min(8, token.length()))
                                        );
                                        return token;
                                    }))
                            .orElseThrow(() -> {
                                log.warn("Refresh failed. No refresh token present | ip={}", ip);
                                return new MissingRefreshTokenException();
                            });

            AuthLoginResult result = authService.refresh(refreshToken);

            log.debug(
                    "Refresh successful | userId={} newRefreshExpiresAt={}",
                    result.user().id(),
                    result.refreshExpiresAtEpochSeconds()
            );

            attachRefreshCookie(response, result);

            log.debug("Refresh flow completed | userId={}", result.user().id());
            return result;

        } catch (RefreshTokenNotFoundException |
                 RefreshTokenExpiredException |
                 RefreshTokenRevokedException |
                 MissingRefreshTokenException ex) {

            RateLimitContext ctx = new RateLimitContext(
                    "/api/v1/auth/refresh",
                    "POST",
                    "invalid-refresh-ip"
            );

            String key = "rl:refresh:invalid:ip:" + ip;

            log.debug(
                    "Invalid refresh detected | ip={} reason={} applying rate limit",
                    ip,
                    ex.getClass().getSimpleName()
            );

            boolean allowed = rateLimiter.allow(
                    key,
                    rateLimitProperties.getInvalidRefresh().getCapacity(),
                    rateLimitProperties.getInvalidRefresh().getRefillPerSecond(),
                    ctx
            );

            if (!allowed) {
                log.warn(
                        "Invalid refresh rate limit exceeded | ip={} capacity={} refillPerSecond={}",
                        ip,
                        rateLimitProperties.getInvalidRefresh().getCapacity(),
                        rateLimitProperties.getInvalidRefresh().getRefillPerSecond()
                );
                throw new RateLimitExceededException("Too many refresh token attempts");
            }

            log.warn(
                    "Invalid refresh attempt allowed | ip={} reason={}",
                    ip,
                    ex.getClass().getSimpleName()
            );

            throw ex;
        }
    }

    /* =========================
       LOGOUT FLOW
       ========================= */

    public void logout(
            AuthPrincipal principal,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        log.debug(
                "Logout flow started | userId={}",
                principal != null ? principal.getUserId() : "anonymous"
        );

        try {
            refreshTokenExtractor.extract(request)
                    .ifPresent(token -> {

                        String userId = authService.resolveUserId(token); // NEW

                        AuditRequestContext ctx = AuditContextHolder.getContext();
                        if (ctx != null) {
                            AuditContextHolder.setContext(
                                    new AuditRequestContext(
                                            ctx.ipAddress(),
                                            ctx.userAgent(),
                                            userId
                                    )
                            );
                        }

                        authService.logout(token);
                    });

        } catch (Exception ex) {
            log.warn(
                    "Logout error ignored | userId={} reason={}",
                    principal != null ? principal.getUserId() : "anonymous",
                    ex.getMessage()
            );
        } finally {
            cookieService.clearRefreshCookie(response);
            cookieService.addNoStoreHeader(response);

            log.debug(
                    "Logout flow completed | userId={}",
                    principal != null ? principal.getUserId() : "anonymous"
            );
        }
    }




    /* =========================
       INTERNAL HELPERS
       ========================= */

    private void attachRefreshCookie(HttpServletResponse response, AuthLoginResult result) {
        long now = Instant.now().getEpochSecond();
        long expiresAt = result.refreshExpiresAtEpochSeconds();
        long ttlSeconds = expiresAt - now;

        log.debug(
                "Preparing refresh cookie | userId={} ttlSeconds={}",
                result.user().id(),
                ttlSeconds
        );

        if (ttlSeconds <= 0) {
            log.error(
                    "Invalid refresh TTL detected | userId={} expiresAt={} now={}",
                    result.user().id(),
                    expiresAt,
                    now
            );
            throw new IllegalStateException("Invalid refresh token TTL");
        }

        cookieService.attachRefreshCookie(
                response,
                result.refreshToken(),
                (int) ttlSeconds
        );

        log.debug(
                "Refresh cookie attached | userId={} ttlSeconds={}",
                result.user().id(),
                ttlSeconds
        );
    }
}
