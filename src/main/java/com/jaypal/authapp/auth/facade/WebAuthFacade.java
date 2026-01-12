package com.jaypal.authapp.auth.facade;

import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.infrastructure.RefreshTokenExtractor;
import com.jaypal.authapp.auth.application.AuthService;
import com.jaypal.authapp.auth.infrastructure.cookie.CookieService;
import com.jaypal.authapp.auth.exception.MissingRefreshTokenException;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class WebAuthFacade {

    private final AuthService authService;
    private final CookieService cookieService;
    private final RefreshTokenExtractor refreshTokenExtractor;

    public AuthLoginResult login(
            AuthPrincipal principal,
            HttpServletResponse response
    ) {
        if (principal == null) {
            throw new IllegalArgumentException("AuthPrincipal must not be null");
        }
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null");
        }

        log.debug("Processing login for user: {}", principal.getUserId());

        final AuthLoginResult result = authService.login(principal);

        attachTokensToResponse(response, result);

        log.debug("Login completed successfully for user: {}", principal.getUserId());

        return result;
    }

    public AuthLoginResult refresh(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        if (request == null) {
            throw new IllegalArgumentException("HttpServletRequest must not be null");
        }
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null");
        }

        log.debug("Processing token refresh flow");

        String refreshToken = refreshTokenExtractor.extract(request)
                .orElseThrow(MissingRefreshTokenException::new);
        log.debug("Refresh headers: X-Refresh-Token={}, Cookie={}",
                request.getHeader("X-Refresh-Token"),
                request.getHeader("Cookie"));

        final AuthLoginResult result = authService.refresh(refreshToken);

        validateLoginResult(result);

        attachTokensToResponse(response, result);

        log.debug("Token refresh completed successfully for user: {}", result.user().getId());

        return result;
    }

    public void logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        if (request == null) {
            throw new IllegalArgumentException("HttpServletRequest must not be null");
        }
        if (response == null) {
            throw new IllegalArgumentException("HttpServletResponse must not be null");
        }

        log.debug("Processing logout flow");

        try {
            refreshTokenExtractor.extract(request)
                    .ifPresent(authService::logout);
        } catch (Exception ex) {
            log.warn("Logout token revocation failed", ex);
        } finally {
            cookieService.clearRefreshCookie(response);
            cookieService.addNoStoreHeader(response);
        }

        log.debug("Logout flow completed");
    }

    private void attachTokensToResponse(HttpServletResponse response, AuthLoginResult result) {
        final int refreshTtl = (int) result.refreshTtlSeconds();

        if (refreshTtl <= 0)  {
            log.error("Invalid refresh TTL: {}", refreshTtl);
            throw new IllegalStateException("Invalid refresh token TTL");
        }

        cookieService.attachRefreshCookie(
                response,
                result.refreshToken(),
                refreshTtl
        );

        cookieService.addNoStoreHeader(response);
    }

    private void validateLoginResult(AuthLoginResult result) {
        if (result == null) {
            throw new IllegalStateException("AuthLoginResult must not be null");
        }
        if (result.refreshToken() == null || result.refreshToken().isBlank()) {
            throw new IllegalStateException("Refresh token must not be null or blank");
        }
        if (result.user() == null) {
            throw new IllegalStateException("Authenticated user must not be null");
        }
    }
}
