package com.jaypal.authapp.oauth.handler;

import com.jaypal.authapp.config.FrontendProperties;
import com.jaypal.authapp.auth.infrastructure.cookie.CookieService;
import com.jaypal.authapp.oauth.dto.OAuthLoginResult;
import com.jaypal.authapp.oauth.application.OAuthLoginService;
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

    private static final String INVALID_AUTH_TYPE_MESSAGE = "Authentication is not an OAuth2AuthenticationToken";

    private final OAuthLoginService oauthLoginService;
    private final CookieService cookieService;
    private final FrontendProperties frontendProperties;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        final OAuth2AuthenticationToken oauthToken = extractOAuthToken(authentication);

        final OAuthLoginResult loginResult = oauthLoginService.login(oauthToken);
        validateLoginResult(loginResult);

        attachSecurityArtifacts(response, loginResult);

        final String redirectUrl = frontendProperties.getSuccessRedirect();
        Objects.requireNonNull(redirectUrl, "Frontend success redirect must be configured");

        log.debug("OAuth2 login successful. Redirecting to {}", redirectUrl);
        response.sendRedirect(redirectUrl);
    }

    private OAuth2AuthenticationToken extractOAuthToken(Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken token)) {
            log.error("OAuth2 success handler invoked with invalid authentication type: {}",
                    authentication != null ? authentication.getClass().getName() : "null");
            throw new IllegalStateException(INVALID_AUTH_TYPE_MESSAGE);
        }
        return token;
    }

    private void validateLoginResult(OAuthLoginResult result) {
        Objects.requireNonNull(result, "OAuthLoginResult must not be null");
        Objects.requireNonNull(result.refreshToken(), "Refresh token must not be null");

        if (result.refreshTtlSeconds() <= 0) {
            throw new IllegalStateException("Invalid refresh token TTL");
        }
    }

    private void attachSecurityArtifacts(
            HttpServletResponse response,
            OAuthLoginResult result
    ) {
        cookieService.attachRefreshCookie(
                response,
                result.refreshToken(),
                Math.toIntExact(result.refreshTtlSeconds())
        );

        cookieService.addNoStoreHeader(response);
    }
}
