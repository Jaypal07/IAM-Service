package com.jaypal.authapp.mapper;

import com.jaypal.authapp.infrastructure.oauth.model.ValidatedOAuthUserInfo;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.Objects;

@Slf4j
public class GithubOAuthUserInfoMapper implements OAuthUserInfoMapper {

    @Override
    public ValidatedOAuthUserInfo map(Map<String, Object> attrs) {
        Objects.requireNonNull(attrs, "OAuth attributes cannot be null");

        if (attrs.isEmpty()) {
            throw new IllegalArgumentException("OAuth attributes cannot be empty");
        }

        final String id = getRequiredString(attrs, "id");
        final String login = getRequiredString(attrs, "login");
        final String email = getOptionalString(attrs, "email");
        final String avatar = getOptionalString(attrs, "avatar_url");

        final String effectiveEmail = email != null && !email.isBlank()
                ? email
                : generateEmailFromLogin(login);

        validateEmail(effectiveEmail);

        log.debug("GitHub OAuth user info mapped - id: {}, login: {}, email: {}",
                id, login, maskEmail(effectiveEmail));

        return new ValidatedOAuthUserInfo(id, effectiveEmail, login, avatar);
    }

    private String getRequiredString(Map<String, Object> attrs, String key) {
        final Object value = attrs.get(key);

        if (value == null) {
            throw new IllegalArgumentException(
                    "Missing required GitHub OAuth attribute: " + key);
        }

        final String stringValue;
        if (value instanceof String str) {
            stringValue = str;
        } else if (value instanceof Number num) {
            stringValue = num.toString();
        } else {
            throw new IllegalArgumentException(
                    "GitHub OAuth attribute '" + key + "' has unsupported type: " + value.getClass().getName());
        }

        if (stringValue.isBlank()) {
            throw new IllegalArgumentException(
                    "GitHub OAuth attribute '" + key + "' is blank");
        }

        return stringValue.trim();
    }

    private String getOptionalString(Map<String, Object> attrs, String key) {
        final Object value = attrs.get(key);

        if (value == null) {
            return null;
        }

        if (!(value instanceof String stringValue)) {
            log.debug("GitHub OAuth attribute '{}' is not a string, ignoring: {}",
                    key, value.getClass().getName());
            return null;
        }

        return stringValue.isBlank() ? null : stringValue.trim();
    }

    private String generateEmailFromLogin(String login) {
        if (login == null || login.isBlank()) {
            throw new IllegalArgumentException("Cannot generate email: login is blank");
        }

        final String sanitizedLogin = login.replaceAll("[^a-zA-Z0-9._-]", "");

        if (sanitizedLogin.isBlank()) {
            throw new IllegalArgumentException("Cannot generate email: login contains no valid characters");
        }

        return sanitizedLogin + "@github.user";
    }

    private void validateEmail(String email) {
        if (!email.contains("@")) {
            throw new IllegalArgumentException("Invalid email format from GitHub OAuth: missing @");
        }

        if (email.length() > 255) {
            throw new IllegalArgumentException("Email from GitHub OAuth exceeds maximum length");
        }

        if (email.startsWith("@") || email.endsWith("@")) {
            throw new IllegalArgumentException("Invalid email format from GitHub OAuth: invalid @ placement");
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
1. CRITICAL: Replaced unsafe toString() with type-safe checks
2. Added support for numeric ID (GitHub returns integer, not string)
3. Added email generation fallback (GitHub email can be null)
4. Added email validation (format, length, placement)
5. Added login sanitization for email generation
6. Added email masking in logs to prevent PII exposure
7. Added null and empty map validation
8. Added trim() to remove whitespace
9. Improved error messages with context
10. Made avatar_url optional (can be null)
*/