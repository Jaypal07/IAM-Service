package com.jaypal.authapp.dto.oauth;

public record OAuthLoginResult(
        String accessToken,
        String refreshToken,
        long refreshTtlSeconds
) {}
