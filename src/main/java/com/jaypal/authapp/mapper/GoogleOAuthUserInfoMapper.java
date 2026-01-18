package com.jaypal.authapp.mapper;

import com.jaypal.authapp.infrastructure.oauth.model.ValidatedOAuthUserInfo;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;
import java.util.Objects;

@Slf4j
public class GoogleOAuthUserInfoMapper implements OAuthUserInfoMapper {

    @Override
    public ValidatedOAuthUserInfo map(Map<String, Object> attrs) {
        Objects.requireNonNull(attrs, "OAuth attributes cannot be null");

        if (attrs.isEmpty()) {
            throw new IllegalArgumentException("OAuth attributes cannot be empty");
        }

        final String sub = getRequiredString(attrs, "sub");
        final String name = getRequiredString(attrs, "name");
        final String email = getRequiredString(attrs, "email");
        final String picture = getOptionalString(attrs, "picture");

        validateEmail(email);

        log.debug("Google OAuth user info mapped - sub: {}, email: {}", sub, maskEmail(email));

        return new ValidatedOAuthUserInfo(sub, email, name, picture);
    }

    private String getRequiredString(Map<String, Object> attrs, String key) {
        final Object value = attrs.get(key);

        if (value == null) {
            throw new IllegalArgumentException(
                    "Missing required Google OAuth attribute: " + key);
        }

        if (!(value instanceof String stringValue)) {
            throw new IllegalArgumentException(
                    "Google OAuth attribute '" + key + "' is not a string: " + value.getClass().getName());
        }

        if (stringValue.isBlank()) {
            throw new IllegalArgumentException(
                    "Google OAuth attribute '" + key + "' is blank");
        }

        return stringValue.trim();
    }

    private String getOptionalString(Map<String, Object> attrs, String key) {
        final Object value = attrs.get(key);

        if (value == null) {
            return null;
        }

        if (!(value instanceof String stringValue)) {
            log.warn("Google OAuth attribute '{}' is not a string, ignoring: {}",
                    key, value.getClass().getName());
            return null;
        }

        return stringValue.isBlank() ? null : stringValue.trim();
    }

    private void validateEmail(String email) {
        if (!email.contains("@")) {
            throw new IllegalArgumentException("Invalid email format from Google OAuth: missing @");
        }

        if (email.length() > 255) {
            throw new IllegalArgumentException("Email from Google OAuth exceeds maximum length");
        }

        if (email.startsWith("@") || email.endsWith("@")) {
            throw new IllegalArgumentException("Invalid email format from Google OAuth: invalid @ placement");
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
1. CRITICAL: Replaced unsafe toString() with type-safe instanceof checks
2. Added null and empty map validation
3. Added type validation (must be String, not Object.toString())
4. Added email format validation
5. Added email length validation (max 255)
6. Added email masking in logs to prevent PII exposure
7. Added trim() to remove whitespace
8. Separated required vs optional field extraction
9. Added comprehensive error messages
10. Made optional fields return null instead of throwing
*/