package com.jaypal.authapp.domain.service.auth;

import com.jaypal.authapp.exception.auth.EmailDeliveryException;
import com.jaypal.authapp.exception.auth.EmailNotRegisteredException;
import com.jaypal.authapp.exception.auth.VerificationTokenExpiredException;
import com.jaypal.authapp.exception.auth.VerificationTokenInvalidException;
import com.jaypal.authapp.domain.infrastructure.email.EmailService;
import com.jaypal.authapp.config.properties.FrontendProperties;
import com.jaypal.authapp.domain.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.entity.VerificationToken;
import com.jaypal.authapp.domain.user.repository.EmailVerificationTokenRepository;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final FrontendProperties frontendProperties;

    @Transactional
    public void createVerificationToken(UUID userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");

        final User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new ResourceNotFoundException("User not found for verification"));

        if (user.isEmailVerified()) {
            log.debug("Verification token creation skipped - already verified: {}", userId);
            return;
        }

        final VerificationToken token = tokenRepository.findByUserId(userId)
                .orElseGet(() -> new VerificationToken(user));

        token.regenerate();
        tokenRepository.save(token);

        final String verifyLink = String.format(
                "%s/email-verify?token=%s",
                frontendProperties.getBaseUrl(),
                token.getToken()
        );

        try {
            emailService.sendVerificationEmail(user.getEmail(), verifyLink);
            log.info("Verification email sent - User ID: {}", userId);
        } catch (Exception ex) {
            log.error("Verification email delivery failed - User ID: {}", userId, ex);
            throw new EmailDeliveryException("Failed to send verification email");
        }
    }

    @Transactional
    public void resendVerificationToken(String email) {
        Objects.requireNonNull(email, "Email cannot be null");

        if (email.isBlank()) {
            log.debug("Resend verification silent fail");
            throw new EmailNotRegisteredException();
        }

        final User user = userRepository.findByEmail(email)
                .orElseThrow(EmailNotRegisteredException::new);

        if (user.isEmailVerified()) {
            log.debug("Verification resend requested for already-verified user: {}", user.getId());
            return;
        }

        createVerificationToken(user.getId());
    }

    @Transactional
    public void verifyEmail(String tokenValue) {
        Objects.requireNonNull(tokenValue, "Token cannot be null");

        if (tokenValue.isBlank()) {
            throw new VerificationTokenInvalidException();
        }

        final VerificationToken token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> {
                    log.warn("Email verification attempted with invalid token");
                    return new VerificationTokenInvalidException();
                });

        if (token.isExpired()) {
            log.warn("Email verification attempted with expired token - User ID: {}",
                    token.getUser().getId());
            tokenRepository.delete(token);
            throw new VerificationTokenExpiredException();
        }

        final UUID userId = token.getUser().getId();

        final User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new ResourceNotFoundException("User missing during email verification"));

        if (user.isEmailVerified()) {
            log.debug("Email verification attempted for already-verified user: {}", userId);
            tokenRepository.delete(token);
            return;
        }

        user.enable();
        userRepository.save(user);
        tokenRepository.delete(token);

        log.info("Email verified successfully - User ID: {}", userId);
    }
}
