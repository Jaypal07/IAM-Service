package com.jaypal.authapp.infrastructure.email;

import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.exception.auth.EmailAlreadyVerifiedException;
import com.jaypal.authapp.exception.auth.EmailDeliveryFailedException;
import com.jaypal.authapp.exception.auth.SilentEmailVerificationResendException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final long RETRY_DELAY_MS = 1000L;

    private final JavaMailSender mailSender;
    private final UserRepository userRepository;

    @Value("${spring.mail.username:noreply@example.com}")
    private String fromAddress;

    /* =====================
       PASSWORD RESET
       ===================== */

    @Override
    public void sendPasswordResetEmail(String to, String resetLink) {
        if (to == null || to.isBlank() || resetLink == null || resetLink.isBlank()) {
            return;
        }

        userRepository.findByEmail(to).ifPresent(user -> {
            if (!user.isEmailVerified()) {
                log.debug("Password reset requested for unverified email");
                return;
            }

            sendEmailWithRetry(
                    to,
                    "Reset Your Password",
                    buildPasswordResetBody(resetLink),
                    "password reset"
            );
        });
    }

    /* =====================
       EMAIL VERIFICATION (RESEND)
       ===================== */

    @Override
    public void sendVerificationEmail(String to, String verifyLink) {
        if (to == null || to.isBlank() || verifyLink == null || verifyLink.isBlank()) {
            return;
        }

        User user = userRepository.findByEmail(to)
                .orElseThrow(() ->
                        new SilentEmailVerificationResendException(
                                "Resend verification requested for non-existent email"
                        )
                );

        // ✅ Already verified → real business error
        if (user.isEmailVerified()) {
            throw new EmailAlreadyVerifiedException(
                    "Email already verified"
            );
        }

        sendEmailWithRetry(
                to,
                "Verify Your Email Address",
                buildVerificationBody(verifyLink),
                "verification"
        );
    }

    /* =====================
       EMAIL SENDING CORE
       ===================== */

    private void sendEmailWithRetry(
            String to,
            String subject,
            String body,
            String emailType
    ) {
        int attempts = 0;
        MailException lastException = null;

        while (attempts < MAX_RETRY_ATTEMPTS) {
            try {
                sendEmail(to, subject, body);
                log.info("{} email sent successfully", capitalize(emailType));
                return;
            } catch (MailException ex) {
                lastException = ex;
                attempts++;

                if (attempts < MAX_RETRY_ATTEMPTS) {
                    log.warn(
                            "{} email failed (attempt {}/{}), retrying...",
                            capitalize(emailType),
                            attempts,
                            MAX_RETRY_ATTEMPTS
                    );

                    try {
                        Thread.sleep(RETRY_DELAY_MS * attempts);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new EmailDeliveryFailedException(
                                "Email sending interrupted",
                                ie
                        );
                    }
                }
            }
        }

        log.error(
                "{} email delivery failed after {} attempts",
                capitalize(emailType),
                MAX_RETRY_ATTEMPTS,
                lastException
        );

        throw new EmailDeliveryFailedException(
                capitalize(emailType) + " email delivery failed",
                lastException
        );
    }

    private void sendEmail(String to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(fromAddress);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);

        mailSender.send(message);
    }

    /* =====================
       EMAIL TEMPLATES
       ===================== */

    private String buildPasswordResetBody(String resetLink) {
        return """
                Hello,

                We received a request to reset your password.
                Click the link below to set a new password:

                %s

                This link will expire in 15 minutes.

                If you did not request this, you can safely ignore this email.

                Best regards,
                Security Team
                """.formatted(resetLink);
    }

    private String buildVerificationBody(String verifyLink) {
        return """
                Welcome!

                Please verify your email address by clicking the link below:

                %s

                This link will expire in 24 hours.

                If you did not create this account, you can ignore this email.

                Best regards,
                Team
                """.formatted(verifyLink);
    }

    private String capitalize(String value) {
        return value.substring(0, 1).toUpperCase() + value.substring(1);
    }
}
