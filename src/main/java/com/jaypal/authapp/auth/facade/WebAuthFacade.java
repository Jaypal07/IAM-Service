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

import java.util.UUID;

@Component
@Slf4j
@RequiredArgsConstructor
public class WebAuthFacade {

    private final AuthService authService;
    private final CookieService cookieService;
    private final RefreshTokenExtractor refreshTokenExtractor;

    public AuthLoginResult login(
            AuthPrincipal principal,
            HttpServletResponse response
    ) {

        AuthLoginResult result = authService.login(principal);

        cookieService.attachRefreshCookie(
                response,
                result.refreshToken(),
                (int) result.refreshTtlSeconds()
        );

        cookieService.addNoStoreHeader(response);
        return result;
    }

    public AuthLoginResult refresh(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String refreshId = UUID.randomUUID().toString().substring(0, 8);
        log.info("REFRESH START [{}]", refreshId);

        String refreshToken =
                refreshTokenExtractor.extract(request)
                        .orElseThrow(MissingRefreshTokenException::new);

        AuthLoginResult result =
                authService.refresh(refreshToken);

        // MUST overwrite cookie
        cookieService.attachRefreshCookie(
                response,
                result.refreshToken(),
                (int) result.refreshTtlSeconds()
        );

        cookieService.addNoStoreHeader(response);
        return result;
    }

    public void logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {

        refreshTokenExtractor.extract(request)
                .ifPresentOrElse(
                        token -> {
                            log.info("LOGOUT: refresh token found");
                            authService.logout(token);
                        },
                        () -> log.warn("LOGOUT: refresh token NOT found")
                );

        cookieService.clearRefreshCookie(response);
        cookieService.addNoStoreHeader(response);
    }
}
