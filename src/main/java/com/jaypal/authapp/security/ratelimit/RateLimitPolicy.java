package com.jaypal.authapp.security.ratelimit;

import java.time.Duration;
import java.util.Map;

public final class RateLimitPolicy {

    private RateLimitPolicy() {}

    public static final Duration WINDOW = Duration.ofMinutes(10);

    public static final Map<String, Integer> LIMITS = Map.of(
            "/api/v1/auth/login", 5,
            "/api/v1/auth/register", 5,
            "/api/v1/auth/forgot-password", 5,
            "/api/v1/auth/reset-password", 5,
            "/api/v1/auth/resend-verification", 5,
            "DEFAULT", 100
    );

    public static int limitFor(String path) {
        return LIMITS.entrySet().stream()
                .filter(e -> path.startsWith(e.getKey()))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(LIMITS.get("DEFAULT"));
    }
}
