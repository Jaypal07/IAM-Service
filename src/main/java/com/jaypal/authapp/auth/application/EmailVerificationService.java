package com.jaypal.authapp.auth.application;

import com.jaypal.authapp.auth.repository.EmailVerificationTokenRepository;
import com.jaypal.authapp.common.exception.email.EmailAlreadyVerifiedException;
import com.jaypal.authapp.common.exception.email.EmailNotRegisteredException;
import com.jaypal.authapp.common.exception.email.VerificationTokenExpiredException;
import com.jaypal.authapp.common.exception.email.VerificationTokenInvalidException;
import com.jaypal.authapp.config.FrontendProperties;
import com.jaypal.authapp.auth.infrastructure.email.EmailService;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.model.VerificationToken;
import com.jaypal.authapp.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final FrontendProperties frontendProperties;

    // ---------------- CREATE / RESEND ----------------

    @Transactional
    public void createVerificationToken(User user) {

        VerificationToken token = tokenRepository.findByUser(user)
                .orElseGet(() -> new VerificationToken(user));

        token.regenerate();
        tokenRepository.save(token);

        String verifyLink =
                frontendProperties.getBaseUrl()
                        + "/email-verify?token=" + token.getToken();

        emailService.sendVerificationEmail(user.getEmail(), verifyLink);
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

        createVerificationToken(user);
    }

    // ---------------- VERIFY ----------------

    @Transactional
    public void verifyEmail(String tokenValue) {

        VerificationToken token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(VerificationTokenInvalidException::new
                );

        if (token.isExpired()) {
            tokenRepository.delete(token);
            throw new VerificationTokenExpiredException();
        }

        User user = token.getUser();
        user.enable();

        tokenRepository.delete(token);
        userRepository.save(user);
    }
}
