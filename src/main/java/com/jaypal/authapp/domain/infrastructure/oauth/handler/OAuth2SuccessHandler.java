package com.jaypal.authapp.domain.infrastructure.oauth.handler;

import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.domain.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.domain.infrastructure.utils.CookieService;
import com.jaypal.authapp.config.properties.FrontendProperties;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.service.oauth.OAuthLoginService;
import com.jaypal.authapp.domain.dto.oauth.OAuthLoginResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private static final long MAX_COOKIE_TTL = Integer.MAX_VALUE;

    private final OAuthLoginService oauthLoginService;
    private final CookieService cookieService;
    private final FrontendProperties frontendProperties;
    private final AuthAuditService auditService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        try {
            final OAuth2AuthenticationToken oauthToken = validateAndExtractToken(authentication);
            final OAuthLoginResult loginResult = oauthLoginService.login(oauthToken);

            validateLoginResult(loginResult);
            attachSecurityArtifacts(response, loginResult);

            final String redirectUrl = getSuccessRedirectUrl();
            auditService.record(
                    AuditCategory.AUTHENTICATION,
                    AuthAuditEvent.OAUTH_LOGIN_SUCCESS,
                    AuditOutcome.SUCCESS,
                    AuditSubject.anonymous(),
                    null,
                    AuthProvider.SYSTEM,
                    AuditContextHolder.getContext()
            );


            log.info("OAuth2 authentication successful - redirecting to: {}", redirectUrl);

            response.sendRedirect(redirectUrl);

        } catch (Exception ex) {
            log.error("OAuth2 success handler failed", ex);
            handleFailure(response, ex);
        }
    }

    private OAuth2AuthenticationToken validateAndExtractToken(Authentication authentication) {
        Objects.requireNonNull(authentication, "Authentication cannot be null");

        if (!(authentication instanceof OAuth2AuthenticationToken token)) {
            final String actualType = authentication.getClass().getSimpleName();
            log.error("OAuth2 success handler invoked with invalid authentication type: {}", actualType);
            throw new IllegalStateException(
                    "Expected OAuth2AuthenticationToken but got: " + actualType);
        }

        if (token.getPrincipal() == null) {
            log.error("OAuth2 authentication token has null principal");
            throw new IllegalStateException("OAuth2 token principal is null");
        }

        if (token.getPrincipal().getAttributes() == null ||
                token.getPrincipal().getAttributes().isEmpty()) {
            log.error("OAuth2 principal has no attributes");
            throw new IllegalStateException("OAuth2 principal attributes are missing");
        }

        return token;
    }

    private void validateLoginResult(OAuthLoginResult result) {
        Objects.requireNonNull(result, "OAuth login result cannot be null");
        Objects.requireNonNull(result.accessToken(), "Access token cannot be null");
        Objects.requireNonNull(result.refreshToken(), "Refresh token cannot be null");

        if (result.accessToken().isBlank()) {
            throw new IllegalStateException("Access token is blank");
        }

        if (result.refreshToken().isBlank()) {
            throw new IllegalStateException("Refresh token is blank");
        }

        if (result.refreshTtlSeconds() <= 0) {
            throw new IllegalStateException("Invalid refresh token TTL: " + result.refreshTtlSeconds());
        }

        if (result.refreshTtlSeconds() > MAX_COOKIE_TTL) {
            log.warn("Refresh token TTL exceeds max cookie age: {}", result.refreshTtlSeconds());
        }
    }

    private void attachSecurityArtifacts(HttpServletResponse response, OAuthLoginResult result) {
        final int refreshTtl = result.refreshTtlSeconds() > MAX_COOKIE_TTL
                ? Integer.MAX_VALUE
                : (int) result.refreshTtlSeconds();

        cookieService.attachRefreshCookie(response, result.refreshToken(), refreshTtl);
        cookieService.addNoStoreHeader(response);
    }

    private String getSuccessRedirectUrl() {
        final String redirectUrl = frontendProperties.getSuccessRedirect();

        if (redirectUrl == null || redirectUrl.isBlank()) {
            throw new IllegalStateException(
                    "Frontend success redirect URL is not configured. Set 'app.frontend.success-redirect'");
        }

        return redirectUrl;
    }

    private void handleFailure(HttpServletResponse response, Exception ex) throws IOException {
        final String failureUrl = frontendProperties.getFailureRedirect();

        if (failureUrl != null && !failureUrl.isBlank()) {
            log.warn("Redirecting to failure URL after OAuth error: {}", failureUrl);
            response.sendRedirect(failureUrl);
        } else {
            log.error("No failure redirect URL configured - returning 500");
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "OAuth authentication processing failed");
        }
    }
}