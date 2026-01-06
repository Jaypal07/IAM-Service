package com.jaypal.authapp.oauth.application;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.oauth.mapper.OAuthUserInfoMapperFactory;
import com.jaypal.authapp.oauth.model.ValidatedOAuthUserInfo;
import com.jaypal.authapp.dto.OAuthLoginResult;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.token.service.RefreshTokenService;
import com.jaypal.authapp.user.model.Provider;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class OAuthLoginService {

    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;

    @AuthAudit(
            event = AuthAuditEvent.OAUTH_LOGIN_SUCCESS,
            provider = "OAUTH"
    )
    @Transactional
    public OAuthLoginResult login(OAuth2AuthenticationToken authentication) {

        Provider provider = Provider.valueOf(
                authentication.getAuthorizedClientRegistrationId().toUpperCase()
        );

        log.info("OAuth login started. provider={}", provider);

        ValidatedOAuthUserInfo info =
                OAuthUserInfoMapperFactory.get(provider)
                        .map(authentication.getPrincipal().getAttributes());

        User user = userRepository
                .findByProviderAndProviderId(provider, info.providerId())
                .orElseGet(() -> {
                    log.info("Creating OAuth user. provider={}, providerId={}",
                            provider, info.providerId());
                    return userRepository.save(
                            User.createOAuth(
                                    provider,
                                    info.providerId(),
                                    info.email(),
                                    info.name(),
                                    info.image()
                            )
                    );
                });

        RefreshToken refreshToken =
                refreshTokenService.issue(
                        user,
                        jwtService.getRefreshTtlSeconds()
                );

        return new OAuthLoginResult(
                jwtService.generateAccessToken(user),
                jwtService.generateRefreshToken(user, refreshToken.getJti()),
                jwtService.getRefreshTtlSeconds()
        );
    }
}
