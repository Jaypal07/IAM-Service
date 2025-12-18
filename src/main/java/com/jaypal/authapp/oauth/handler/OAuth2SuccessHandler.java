package com.jaypal.authapp.oauth.handler;

import com.jaypal.authapp.security.cookie.CookieService;
import com.jaypal.authapp.oauth.service.OAuthLoginResult;
import com.jaypal.authapp.oauth.service.OAuthLoginService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler
        implements AuthenticationSuccessHandler {

    private final OAuthLoginService oauthLoginService;
    private final CookieService cookieService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            throw new IllegalStateException(
                    "Invalid OAuth authentication"
            );
        }

        OAuthLoginResult result =
                oauthLoginService.login(oauthToken);

        cookieService.attachRefreshCookie(
                response,
                result.refreshToken(),
                (int) result.refreshTtlSeconds()
        );
        cookieService.addNoStoreHeader(response);

        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write("Login Successful");
    }
}
