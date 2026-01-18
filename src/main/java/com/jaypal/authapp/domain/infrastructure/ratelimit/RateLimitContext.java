package com.jaypal.authapp.domain.infrastructure.ratelimit;

public record RateLimitContext(
        String endpoint,
        String method,
        String scope
) {
}
