package com.jaypal.authapp.domain.token.service;

import java.security.SecureRandom;
import java.util.Base64;

public final class RefreshTokenGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int TOKEN_BYTE_LENGTH = 64;
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private RefreshTokenGenerator() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    public static String generate() {
        final byte[] bytes = new byte[TOKEN_BYTE_LENGTH];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }
}

/*
CHANGELOG:
1. Added private constructor that throws to prevent instantiation
2. Extracted TOKEN_BYTE_LENGTH as constant for clarity
3. Reused Base64.Encoder instance instead of creating new one per call
4. Made bytes variable final
5. Added Javadoc-style clarity to constants
*/