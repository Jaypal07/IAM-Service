package com.jaypal.authapp.auth.application;

import com.jaypal.authapp.auth.exception.EmailAlreadyVerifiedException;
import com.jaypal.authapp.auth.exception.EmailNotRegisteredException;
import com.jaypal.authapp.auth.exception.VerificationTokenExpiredException;
import com.jaypal.authapp.auth.exception.VerificationTokenInvalidException;
import com.jaypal.authapp.auth.infrastructure.email.EmailService;
import com.jaypal.authapp.config.FrontendProperties;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.model.VerificationToken;
import com.jaypal.authapp.user.repository.EmailVerificationTokenRepository;
import com.jaypal.authapp.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final FrontendProperties frontendProperties;

    // ---------------- CREATE / RESEND ----------------

    /**
     * INTERNAL USE ONLY
     * Called after registration commit or resend flow.
     */
    @Transactional
    public void createVerificationToken(UUID userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new IllegalStateException("User not found for verification"));

        VerificationToken token = tokenRepository.findByUserId(userId)
                .orElseGet(() -> new VerificationToken(user));

        token.regenerate();
        tokenRepository.save(token);

        String verifyLink =
                frontendProperties.getBaseUrl()
                        + "/email-verify?token=" + token.getToken();

        emailService.sendVerificationEmail(
                user.getEmail(),
                verifyLink
        );

        log.info("Verification email sent. userId={}", userId);
    }

    /**
     * SECURITY CONTRACT
     *
     * - If email is NOT registered -> silently succeed (throw internal exception)
     * - If email is already verified -> silently succeed (throw internal exception)
     * - If email is valid and unverified -> resend token
     *
     * Controller MUST swallow EmailNotRegisteredException
     * and EmailAlreadyVerifiedException.
     */
    @Transactional
    public void resendVerificationToken(String email) {

        User user = userRepository.findByEmail(email)
                .orElseThrow(EmailNotRegisteredException::new);

        if (user.isEnabled()) {
            throw new EmailAlreadyVerifiedException();
        }

        createVerificationToken(user.getId());
    }

    // ---------------- VERIFY ----------------

    @Transactional
    public void verifyEmail(String tokenValue) {

        VerificationToken token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(VerificationTokenInvalidException::new);

        if (token.isExpired()) {
            tokenRepository.delete(token);
            throw new VerificationTokenExpiredException();
        }

        UUID userId = token.getUser().getId();

        User user = userRepository.findById(userId)
                .orElseThrow(() ->
                        new IllegalStateException("User missing during verification"));

        user.enable();

        tokenRepository.delete(token);
        userRepository.save(user);

        log.info("Email verified. userId={}", userId);
    }
}
