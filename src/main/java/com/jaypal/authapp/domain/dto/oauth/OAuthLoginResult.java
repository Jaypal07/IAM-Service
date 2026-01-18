package com.jaypal.authapp.domain.dto.oauth;

public record OAuthLoginResult(
        String accessToken,
        String refreshToken,
        long refreshTtlSeconds
) {}
