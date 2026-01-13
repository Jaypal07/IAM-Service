package com.jaypal.authapp.auth.application;

import com.jaypal.authapp.auth.dto.AuthLoginResult;
import com.jaypal.authapp.auth.event.UserRegisteredEvent;
import com.jaypal.authapp.auth.exception.*;
import com.jaypal.authapp.auth.infrastructure.email.EmailService;
import com.jaypal.authapp.config.FrontendProperties;
import com.jaypal.authapp.config.PasswordPolicy;
import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.token.application.IssuedRefreshToken;
import com.jaypal.authapp.token.application.RefreshTokenService;
import com.jaypal.authapp.token.model.RefreshToken;
import com.jaypal.authapp.user.application.PermissionService;
import com.jaypal.authapp.user.application.UserService;
import com.jaypal.authapp.user.dto.UserCreateRequest;
import com.jaypal.authapp.user.model.PasswordResetToken;
import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.PasswordResetTokenRepository;
import com.jaypal.authapp.user.repository.UserRepository;
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

        if (request == null) {
            throw new IllegalArgumentException("UserCreateRequest must not be null");
        }

        final User user = userService.createAndReturnDomainUser(request);

        log.debug("User registered successfully - ID: {}", user.getId());

        eventPublisher.publishEvent(new UserRegisteredEvent(user.getId()));
    }

    @Transactional(readOnly = true)
    public AuthLoginResult login(AuthPrincipal principal) {
        Objects.requireNonNull(principal, "Principal cannot be null");
        Objects.requireNonNull(principal.getUserId(), "User ID cannot be null");

        final User user = userRepository.findById(principal.getUserId())
                .orElseThrow(AuthenticatedUserMissingException::new);

        if (!user.isEnabled()) {
            log.warn("Login attempt for disabled user: {}", user.getId());
            throw new AuthenticatedUserMissingException();
        }

        log.info("User logged in successfully - ID: {}", user.getId());

        return issueTokens(user);
    }

    @Transactional
    public AuthLoginResult refresh(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            log.warn("Refresh attempt with null or blank token");
            throw new InvalidRefreshTokenException();
        }

        final RefreshToken current = refreshTokenService.validate(rawRefreshToken);
        final IssuedRefreshToken next = refreshTokenService.rotate(
                current,
                jwtService.getRefreshTtlSeconds()
        );

        final UUID userId = current.getUserId();
        final User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("User not found during token refresh: {}", userId);
                    return new AuthenticatedUserMissingException();
                });

        if (!user.isEnabled()) {
            log.warn("Token refresh attempted for disabled user: {}", userId);
            throw new AuthenticatedUserMissingException();
        }

        final Set<PermissionType> permissions = permissionService.resolvePermissions(userId);

        log.debug("Token refreshed successfully - User ID: {}", userId);

        return new AuthLoginResult(
                user,
                jwtService.generateAccessToken(user, permissions),
                next.token(),
                next.expiresAt().getEpochSecond()
        );
    }

    @Transactional
    public void logout(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            log.debug("Logout called with null/blank token - no action taken");
            return;
        }

        try {
            refreshTokenService.revoke(rawRefreshToken);
            log.debug("User logged out successfully");
        } catch (Exception ex) {
            log.warn("Logout revocation failed (token may be invalid): {}", ex.getMessage());
        }
    }

    @Transactional
    public void logoutAllSessions(UUID userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");

        final User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.error("Logout-all failed. User not found: {}", userId);
                    return new AuthenticatedUserMissingException();
                });

        user.bumpPermissionVersion();
        refreshTokenService.revokeAllForUser(userId);

        userRepository.save(user);

        log.info("All sessions revoked for user: {}", userId);
    }

    @Transactional
    public void verifyEmail(String token) {

        if (token == null || token.isBlank()) {
            throw new VerificationTokenInvalidException();
        }

        emailVerificationService.verifyEmail(token);
    }

    @Transactional
    public void resendVerification(String email) {

        if (email == null || email.isBlank()) {
            log.warn("Resend verification called with blank email");
            return;
        }

        try {
            emailVerificationService.resendVerificationToken(email);
        } catch (EmailNotRegisteredException | EmailAlreadyVerifiedException ex) {
            log.debug("Resend verification silent fail: {}", ex.getClass().getSimpleName());
        }
    }

    @Transactional
    public void initiatePasswordReset(String email) {

        if (email == null || email.isBlank()) {
            log.debug("Password reset requested with null or blank email");
            return;
        }

        userRepository.findByEmail(email).ifPresentOrElse(
                user -> {
                    passwordResetTokenRepository.deleteAllByUser_Id(user.getId());

                    final String tokenValue = UUID.randomUUID().toString();
                    final PasswordResetToken token = PasswordResetToken.builder()
                            .token(tokenValue)
                            .user(user)
                            .expiresAt(Instant.now().plusSeconds(PASSWORD_RESET_TTL_SECONDS))
                            .build();

                    passwordResetTokenRepository.save(token);

                    final String resetLink = String.format(
                            "%s/reset-password?token=%s",
                            frontendProperties.getBaseUrl(),
                            tokenValue
                    );

                    try {
                        emailService.sendPasswordResetEmail(user.getEmail(), resetLink);
                        log.debug("Password reset email sent - User ID: {}", user.getId());
                    } catch (Exception ex) {
                        log.error("Password reset email failed - User ID: {}", user.getId(), ex);
                    }
                },
                () -> log.debug("Password reset requested for non-existent email")
        );
    }

    @Transactional
    public void resetPassword(String tokenValue, String rawPassword) {
        if (tokenValue == null || tokenValue.isBlank()) {
            throw new PasswordResetTokenInvalidException();
        }
        if (rawPassword == null) {
            throw new IllegalArgumentException("Password must not be null");
        }

        passwordPolicy.validate(rawPassword);

        final PasswordResetToken token = passwordResetTokenRepository
                .findByToken(tokenValue)
                .orElseThrow(PasswordResetTokenInvalidException::new);

        if (token.isUsed()) {
            log.warn("Password reset attempted with already-used token");
            throw new PasswordResetTokenExpiredException();
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            log.warn("Password reset attempted with expired token");
            passwordResetTokenRepository.delete(token);
            throw new PasswordResetTokenExpiredException();
        }

        final User user = token.getUser();
        user.changePassword(passwordEncoder.encode(rawPassword));
        user.bumpPermissionVersion();
        token.setUsed(true);

        userRepository.save(user);
        passwordResetTokenRepository.save(token);

        log.debug("Password reset successful - User ID: {}", user.getId());
    }

    private AuthLoginResult issueTokens(User user) {
        final Set<PermissionType> permissions = permissionService.resolvePermissions(user.getId());

        final IssuedRefreshToken refreshToken = refreshTokenService.issue(
                user.getId(),
                jwtService.getRefreshTtlSeconds()
        );

        return new AuthLoginResult(
                user,
                jwtService.generateAccessToken(user, permissions),
                refreshToken.token(),
                refreshToken.expiresAt().getEpochSecond()
        );
    }

}