package com.jaypal.authapp.oauth;

import com.jaypal.authapp.entity.Provider;
import com.jaypal.authapp.entity.RefreshToken;
import com.jaypal.authapp.entity.User;
import com.jaypal.authapp.repository.RefreshTokenRepository;
import com.jaypal.authapp.repository.UserRepository;
import com.jaypal.authapp.security.CookieService;
import com.jaypal.authapp.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

@Component
@AllArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log =
            LoggerFactory.getLogger(OAuth2SuccessHandler.class);

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieService cookieService;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {

        log.info("OAuth2 authentication success");
        log.info("Authentication object: {}", authentication);

        OAuth2AuthenticationToken token =
                (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = token.getPrincipal();

        String registrationId =
                token.getAuthorizedClientRegistrationId();

        log.info("Registration Id: {}", registrationId);
        log.info("OAuth attributes: {}", oAuth2User.getAttributes());

        Provider provider =
                Provider.valueOf(registrationId.toUpperCase());

        OAuthUserInfo userInfo =
                OAuthUserInfo.from(provider, oAuth2User.getAttributes());

        User user = userRepository
                .findByProviderAndProviderId(provider, userInfo.providerId())
                .orElseGet(() -> createUser(provider, userInfo));

        RefreshToken refreshToken = createRefreshToken(user);
        refreshTokenRepository.save(refreshToken);

        String accessToken =
                jwtService.generateAccessToken(user);

        String refreshJwt =
                jwtService.generateRefreshToken(
                        user,
                        refreshToken.getJti()
                );

        cookieService.attachRefreshCookie(
                response,
                refreshJwt,
                (int) jwtService.getRefreshTtlSeconds()
        );

        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write("Login Successful");
    }

    private User createUser(Provider provider, OAuthUserInfo info) {

        log.info(
                "Creating new OAuth user. Provider: {}, ProviderId: {}",
                provider,
                info.providerId()
        );

        return userRepository.save(
                User.builder()
                        .provider(provider)
                        .providerId(info.providerId())
                        .email(info.email())
                        .name(info.name())
                        .image(info.image())
                        .enabled(true)
                        .build()
        );
    }

    private RefreshToken createRefreshToken(User user) {

        return RefreshToken.builder()
                .jti(UUID.randomUUID().toString())
                .user(user)
                .revoked(false)
                .expiresAt(
                        Instant.now()
                                .plusSeconds(
                                        jwtService.getRefreshTtlSeconds()
                                )
                )
                .build();
    }
}
