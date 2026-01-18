package com.jaypal.authapp.domain.token.vo;

import java.time.Instant;

public record IssuedRefreshToken(
        String token,
        Instant expiresAt
) {}
