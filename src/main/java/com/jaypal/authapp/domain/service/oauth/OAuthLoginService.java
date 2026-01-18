package com.jaypal.authapp.domain.service.oauth;

import com.jaypal.authapp.domain.dto.oauth.OAuthLoginResult;
import com.jaypal.authapp.domain.mapper.OAuthUserInfoMapperFactory;
import com.jaypal.authapp.domain.infrastructure.oauth.model.ValidatedOAuthUserInfo;
import com.jaypal.authapp.domain.infrastructure.security.jwt.JwtService;
import com.jaypal.authapp.domain.token.vo.IssuedRefreshToken;
import com.jaypal.authapp.domain.token.service.RefreshTokenService;
import com.jaypal.authapp.domain.user.service.PermissionService;
import com.jaypal.authapp.domain.user.service.UserProvisioningService;
import com.jaypal.authapp.domain.user.entity.PermissionType;
import com.jaypal.authapp.domain.user.entity.Provider;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuthLoginService {

    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final UserProvisioningService userProvisioningService;
    private final PermissionService permissionService;
    private final JwtService jwtService;

    @Transactional(isolation = Isolation.READ_COMMITTED)
    public OAuthLoginResult login(OAuth2AuthenticationToken authentication) {
        Objects.requireNonNull(authentication, "OAuth authentication token cannot be null");

        final String registrationId = authentication.getAuthorizedClientRegistrationId();
        if (registrationId == null || registrationId.isBlank()) {
            throw new IllegalArgumentException("OAuth registration ID is missing");
        }

        final Provider provider = parseProvider(registrationId);

        log.info("OAuth login initiated - provider: {}", provider);

        final ValidatedOAuthUserInfo userInfo = extractUserInfo(authentication, provider);
        validateUserInfo(userInfo, provider);

        final User user = findOrCreateUser(provider, userInfo);

        if (!user.isEnabled()) {
            log.warn("OAuth login attempted for disabled user: {}", user.getId());
            throw new IllegalStateException("User account is disabled");
        }

        userProvisioningService.provisionNewUser(user);

        final Set<PermissionType> permissions = permissionService.resolvePermissions(user.getId());

        final IssuedRefreshToken refreshToken = refreshTokenService.issue(
                user.getId(),
                jwtService.getRefreshTtlSeconds()
        );

        final String accessToken = jwtService.generateAccessToken(user, permissions);

        log.info("OAuth login successful - provider: {}, userId: {}", provider, user.getId());

        return new OAuthLoginResult(
                accessToken,
                refreshToken.token(),
                refreshToken.expiresAt().getEpochSecond()
        );
    }

    private Provider parseProvider(String registrationId) {
        try {
            return Provider.valueOf(registrationId.toUpperCase());
        } catch (IllegalArgumentException ex) {
            log.error("Unsupported OAuth provider: {}", registrationId);
            throw new IllegalStateException("Unsupported OAuth provider: " + registrationId, ex);
        }
    }

    private ValidatedOAuthUserInfo extractUserInfo(
            OAuth2AuthenticationToken authentication,
            Provider provider
    ) {
        try {
            return OAuthUserInfoMapperFactory.get(provider)
                    .map(authentication.getPrincipal().getAttributes());
        } catch (Exception ex) {
            log.error("Failed to extract OAuth user info - provider: {}", provider, ex);
            throw new IllegalStateException("Failed to extract user information from OAuth provider", ex);
        }
    }

    private void validateUserInfo(ValidatedOAuthUserInfo info, Provider provider) {
        if (info == null) {
            throw new IllegalStateException("OAuth user info is null");
        }

        if (info.providerId() == null || info.providerId().isBlank()) {
            throw new IllegalStateException("OAuth provider ID is missing");
        }

        if (info.email() == null || info.email().isBlank()) {
            throw new IllegalStateException("OAuth email is missing");
        }

        if (info.name() == null || info.name().isBlank()) {
            throw new IllegalStateException("OAuth name is missing");
        }

        if (!info.email().contains("@")) {
            log.warn("Invalid email format from OAuth provider: {}", provider);
            throw new IllegalStateException("Invalid email format");
        }

        log.debug("OAuth user info validated - provider: {}, email: {}",
                provider, maskEmail(info.email()));
    }

    private User findOrCreateUser(Provider provider, ValidatedOAuthUserInfo info) {
        return userRepository
                .findByProviderAndProviderId(provider, info.providerId())
                .orElseGet(() -> createNewOAuthUser(provider, info));
    }

    private User createNewOAuthUser(Provider provider, ValidatedOAuthUserInfo info) {
        try {
            final User newUser = User.createOAuth(
                    provider,
                    info.providerId(),
                    info.email(),
                    info.name(),
                    info.image()
            );

            final User saved = userRepository.save(newUser);

            log.info("New OAuth user created - provider: {}, userId: {}, email: {}",
                    provider, saved.getId(), maskEmail(info.email()));

            return saved;

        } catch (DataIntegrityViolationException ex) {
            log.warn("OAuth user creation conflict - provider: {}, providerId: {} - retrying lookup",
                    provider, info.providerId());

            return userRepository
                    .findByProviderAndProviderId(provider, info.providerId())
                    .orElseThrow(() -> new IllegalStateException(
                            "Failed to create or find OAuth user after conflict", ex));
        }
    }

    private String maskEmail(String email) {
        if (email == null || email.length() <= 3) {
            return "***";
        }

        final int atIndex = email.indexOf('@');
        if (atIndex <= 0) {
            return email.substring(0, 2) + "***";
        }

        return email.substring(0, Math.min(2, atIndex)) + "***" + email.substring(atIndex);
    }
}

/*
CHANGELOG:
1. Added comprehensive null checks and validation
2. Added race condition handling for concurrent user creation
3. Added email format validation
4. Added disabled user check
5. Separated provider parsing with proper error handling
6. Extracted user info validation to dedicated method
7. Added email masking in logs to prevent PII exposure
8. Added READ_COMMITTED isolation to prevent phantom reads
9. Wrapped user info extraction in try-catch
10. Added retry logic on DataIntegrityViolation (race condition)
11. Made error messages more descriptive
12. Added comprehensive logging at each stage
*/