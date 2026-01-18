package com.jaypal.authapp.domain.service.auth;

import com.jaypal.authapp.domain.dto.auth.AuthLoginResult;
import com.jaypal.authapp.domain.event.UserRegisteredEvent;
import com.jaypal.authapp.domain.infrastructure.email.EmailService;
import com.jaypal.authapp.config.properties.FrontendProperties;
import com.jaypal.authapp.config.properties.PasswordPolicy;
import com.jaypal.authapp.domain.infrastructure.security.jwt.JwtService;
import com.jaypal.authapp.domain.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.domain.token.vo.IssuedRefreshToken;
import com.jaypal.authapp.domain.token.service.RefreshTokenService;
import com.jaypal.authapp.domain.token.exception.RefreshTokenExpiredException;
import com.jaypal.authapp.domain.token.exception.RefreshTokenNotFoundException;
import com.jaypal.authapp.domain.token.exception.RefreshTokenRevokedException;
import com.jaypal.authapp.domain.token.entity.RefreshToken;
import com.jaypal.authapp.domain.user.service.PermissionService;
import com.jaypal.authapp.domain.user.service.UserService;
import com.jaypal.authapp.domain.dto.user.UserCreateRequest;
import com.jaypal.authapp.domain.dto.user.UserResponseDto;
import com.jaypal.authapp.domain.mapper.UserMapper;
import com.jaypal.authapp.domain.user.entity.PasswordResetToken;
import com.jaypal.authapp.domain.user.entity.PermissionType;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.PasswordResetTokenRepository;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.exception.auth.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final long PASSWORD_RESET_TTL_SECONDS = 900L;

    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final PermissionService permissionService;
    private final UserService userService;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final FrontendProperties frontendProperties;
    private final EmailVerificationService emailVerificationService;
    private final ApplicationEventPublisher eventPublisher;
    private final PasswordPolicy passwordPolicy;

    @Transactional
    public void register(UserCreateRequest request) {
        Objects.requireNonNull(request, "UserCreateRequest must not be null");

        log.debug("Registration requested. email={}", request.email());

        UserResponseDto user = userService.createUser(request);

        log.info("User registered successfully. userId={}", user.id());

        eventPublisher.publishEvent(new UserRegisteredEvent(user.id()));
        log.debug("UserRegisteredEvent published. userId={}", user.id());
    }

    @Transactional
    public AuthLoginResult login(AuthPrincipal principal) {
        Objects.requireNonNull(principal, "Principal cannot be null");
        Objects.requireNonNull(principal.getUserId(), "User ID cannot be null");

        UUID userId = principal.getUserId();
        log.debug("Login invoked. userId={}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(AuthenticatedUserMissingException::new);

        if (!user.isEnabled()) {
            log.warn("Login blocked for disabled user. userId={}", userId);
            throw new AuthenticatedUserMissingException();
        }

        log.info("User logged in successfully. userId={}", userId);

        return issueTokens(user);
    }

    @Transactional
    public AuthLoginResult refresh(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            log.warn("Refresh attempted with blank token");
            throw new InvalidRefreshTokenException("Refresh token is invalid");
        }

        RefreshToken current = refreshTokenService.validate(rawRefreshToken);
        IssuedRefreshToken next = refreshTokenService.rotate(
                current.getId(),
                jwtService.getRefreshTtlSeconds()
        );

        UUID userId = current.getUserId();

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("Refresh failed. User not found. userId={}", userId);
                    return new AuthenticatedUserMissingException();
                });

        if (!user.isEnabled()) {
            log.warn("Refresh blocked for disabled user. userId={}", userId);
            throw new AuthenticatedUserMissingException();
        }

        Set<PermissionType> permissions = permissionService.resolvePermissions(userId);

        log.debug(
                "Refresh successful. userId={} permissions={} permVersion={}",
                userId,
                permissions.size(),
                user.getPermissionVersion()
        );

        return new AuthLoginResult(
                UserMapper.toResponse(user, permissions),
                jwtService.generateAccessToken(user, permissions),
                next.token(),
                next.expiresAt().getEpochSecond()
        );
    }

    @Transactional
    public void logout(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            log.debug("Logout called without refresh token");
            return;
        }

        try {
            refreshTokenService.revoke(rawRefreshToken);
            log.debug("Refresh token revoked");
        } catch (RefreshTokenNotFoundException ex) {
            log.debug("Refresh token already revoked or expired");
        } catch (Exception ex) {
            log.warn(
                    "Unexpected error during refresh token revoke | type={} message={}",
                    ex.getClass().getSimpleName(),
                    ex.getMessage()
            );
        }
    }


    @Transactional
    public void logoutAllSessions(UUID userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("Logout-all failed. User not found. userId={}", userId);
                    return new AuthenticatedUserMissingException();
                });

        user.bumpPermissionVersion();
        refreshTokenService.revokeAllForUser(userId);
        userRepository.save(user);

        log.info(
                "All sessions revoked. userId={} permVersion={}",
                userId,
                user.getPermissionVersion()
        );
    }

    @Transactional
    public void verifyEmail(String token) {
        if (token == null || token.isBlank()) {
            throw new VerificationTokenInvalidException();
        }

        log.debug("Email verification requested");
        emailVerificationService.verifyEmail(token);
    }

    public void resendVerification(String email) {
        if (email == null || email.isBlank()) {
            log.warn("Resend verification called with blank email");
            return;
        }

        emailVerificationService.resendVerificationToken(email);
    }

    @Transactional
    public void initiatePasswordReset(String email) {
        userRepository.findByEmail(email).ifPresentOrElse(user -> {

            if (!user.isEnabled()) {
                log.warn("Password reset blocked for disabled user. userId={}", user.getId());
                return;
            }

            if (!user.isEmailVerified()) {
                log.warn("Password reset blocked for unverified email. userId={}", user.getId());
                return;
            }

            passwordResetTokenRepository.deleteAllByUser_Id(user.getId());

            String tokenValue = UUID.randomUUID().toString();

            PasswordResetToken token = PasswordResetToken.builder()
                    .token(tokenValue)
                    .user(user)
                    .expiresAt(Instant.now().plusSeconds(PASSWORD_RESET_TTL_SECONDS))
                    .build();

            passwordResetTokenRepository.save(token);

            String resetLink = frontendProperties.getBaseUrl()
                    + "/reset-password?token=" + tokenValue;

            try {
                emailService.sendPasswordResetEmail(user.getEmail(), resetLink);
                log.info("Password reset email sent. userId={}", user.getId());
            } catch (Exception ex) {
                log.error("Password reset email failed. userId={}", user.getId(), ex);
            }

        }, () -> log.debug("Password reset requested for non-existent email"));

        // silent exit to prevent enumeration
    }

    @Transactional
    public void resetPassword(String tokenValue, String rawPassword) {
        if (tokenValue == null || tokenValue.isBlank()) {
            throw new PasswordResetTokenInvalidException();
        }

        passwordPolicy.validate(rawPassword);

        PasswordResetToken token = passwordResetTokenRepository
                .findByToken(tokenValue)
                .orElseThrow(PasswordResetTokenInvalidException::new);

        if (token.isUsed() || token.getExpiresAt().isBefore(Instant.now())) {
            log.warn("Expired or used password reset token");
            passwordResetTokenRepository.delete(token);
            throw new PasswordResetTokenExpiredException();
        }

        User user = token.getUser();
        user.changePassword(passwordEncoder.encode(rawPassword));
        user.bumpPermissionVersion();
        token.setUsed(true);

        userRepository.save(user);
        passwordResetTokenRepository.save(token);

        log.info(
                "Password reset successful. userId={} permVersion={}",
                user.getId(),
                user.getPermissionVersion()
        );
    }

    private AuthLoginResult issueTokens(User user) {
        Set<PermissionType> permissions = permissionService.resolvePermissions(user.getId());

        IssuedRefreshToken refreshToken = refreshTokenService.issue(
                user.getId(),
                jwtService.getRefreshTtlSeconds()
        );

        log.debug(
                "Issuing tokens. userId={} permissions={} permVersion={}",
                user.getId(),
                permissions.size(),
                user.getPermissionVersion()
        );

        return new AuthLoginResult(
                UserMapper.toResponse(user, permissions),
                jwtService.generateAccessToken(user, permissions),
                refreshToken.token(),
                refreshToken.expiresAt().getEpochSecond()
        );
    }
    @Transactional(readOnly = true)
    public String resolveUserId(String rawRefreshToken) {
        try {
            return refreshTokenService
                    .validate(rawRefreshToken)   // already exists
                    .getUserId()
                    .toString();
        } catch (RefreshTokenNotFoundException |
                 RefreshTokenExpiredException |
                 RefreshTokenRevokedException ex) {

            // Logout must be best-effort and audit-safe
            log.debug(
                    "Unable to resolve userId from refresh token for audit | reason={}",
                    ex.getClass().getSimpleName()
            );
            return null;
        }
    }

}
