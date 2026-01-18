package com.jaypal.authapp.infrastructure.ratelimit;

public record RateLimitContext(
        String endpoint,
        String method,
        String scope
) {
}
