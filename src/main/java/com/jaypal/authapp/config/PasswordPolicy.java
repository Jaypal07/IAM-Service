package com.jaypal.authapp.config;

import com.jaypal.authapp.auth.exception.PasswordPolicyViolationException;
import org.springframework.context.annotation.Configuration;

import java.util.regex.Pattern;

@Configuration
public class PasswordPolicy {

    private static final int MIN_LENGTH = 8;
    private static final int MAX_LENGTH = 72;

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{" + MIN_LENGTH + ",}$"
    );

    public void validate(String password) {
        if (password == null) {
            throw new PasswordPolicyViolationException("Password must not be null");
        }

        if (password.length() < MIN_LENGTH) {
            throw new PasswordPolicyViolationException(
                    "Password must be at least " + MIN_LENGTH + " characters"
            );
        }

        if (password.length() > MAX_LENGTH) {
            throw new PasswordPolicyViolationException(
                    "Password must not exceed " + MAX_LENGTH + " characters"
            );
        }

        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new PasswordPolicyViolationException(
                    "Password must contain uppercase, lowercase, and digit"
            );
        }

        if (password.contains(" ")) {
            throw new PasswordPolicyViolationException(
                    "Password must not contain spaces"
            );
        }
    }
}

