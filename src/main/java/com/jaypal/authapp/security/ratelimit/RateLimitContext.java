package com.jaypal.authapp.security.ratelimit;

public record RateLimitContext(
        String endpoint,
        String method,
        String scope
) {
}
